use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use parking_lot::RwLock;
use tokio::net::UdpSocket;
use tracing::{debug, info, warn};

use crate::config::UpstreamConfig;
use crate::dns::packet;

/// Result of a successful upstream query
pub struct UpstreamResult {
    pub response: Vec<u8>,
    pub upstream_name: String,
    pub latency: Duration,
    pub original_ttl: u32,
}

/// Per-upstream statistics and trust data
struct UpstreamState {
    config: UpstreamConfig,
    total_queries: AtomicU64,
    total_failures: AtomicU64,
    latency_history: RwLock<Vec<Duration>>, // Recent latencies
    trust_score: RwLock<f64>,               // 0.0 - 1.0
    disabled: RwLock<bool>,                 // Disabled by trust scorer
}

pub struct UpstreamManager {
    upstreams: Vec<UpstreamState>,
}

impl UpstreamManager {
    pub async fn new(configs: &[UpstreamConfig]) -> anyhow::Result<Self> {
        if configs.is_empty() {
            return Err(anyhow::anyhow!("At least one upstream server is required"));
        }

        let upstreams = configs
            .iter()
            .map(|c| UpstreamState {
                config: c.clone(),
                total_queries: AtomicU64::new(0),
                total_failures: AtomicU64::new(0),
                latency_history: RwLock::new(Vec::new()),
                trust_score: RwLock::new(1.0),
                disabled: RwLock::new(false),
            })
            .collect();

        info!("Upstream manager initialized with {} upstreams", configs.len());
        Ok(Self { upstreams })
    }

    /// Race all enabled upstreams - first response wins
    pub async fn race_query(&self, query: &[u8]) -> anyhow::Result<UpstreamResult> {
        let enabled: Vec<&UpstreamState> = self.upstreams
            .iter()
            .filter(|u| !*u.disabled.read())
            .collect();

        if enabled.is_empty() {
            // All disabled - re-enable all and try anyway
            warn!("All upstreams disabled! Re-enabling all.");
            for u in &self.upstreams {
                *u.disabled.write() = false;
            }
            return self.race_query_inner(&self.upstreams.iter().collect::<Vec<_>>(), query).await;
        }

        self.race_query_inner(&enabled, query).await
    }

    async fn race_query_inner(&self, upstreams: &[&UpstreamState], query: &[u8]) -> anyhow::Result<UpstreamResult> {
        use tokio::select;

        // Spawn all upstream queries simultaneously
        let mut tasks = Vec::new();
        for upstream in upstreams {
            let query_data = query.to_vec();
            let addr: SocketAddr = format!("{}:{}", upstream.config.address, upstream.config.port)
                .parse()
                .map_err(|e| anyhow::anyhow!("Invalid upstream address: {}", e))?;
            let timeout = Duration::from_millis(upstream.config.timeout_ms);
            let name = upstream.config.name.clone();

            tasks.push(tokio::spawn(async move {
                let start = Instant::now();
                match Self::query_upstream(&query_data, addr, timeout).await {
                    Ok(response) => {
                        let latency = start.elapsed();
                        let original_ttl = Self::extract_ttl(&response).unwrap_or(0);
                        Ok(UpstreamResult {
                            response,
                            upstream_name: name,
                            latency,
                            original_ttl,
                        })
                    }
                    Err(e) => Err((name, e)),
                }
            }));
        }

        // Wait for first successful response
        let (result, _remaining) = futures_select_first(tasks).await;

        match result {
            Ok(Ok(upstream_result)) => {
                // Record success
                if let Some(u) = self.upstreams.iter().find(|u| u.config.name == upstream_result.upstream_name) {
                    u.total_queries.fetch_add(1, Ordering::Relaxed);
                }
                Ok(upstream_result)
            }
            Ok(Err((name, e))) => {
                // Record failure
                if let Some(u) = self.upstreams.iter().find(|u| u.config.name == name) {
                    u.total_failures.fetch_add(1, Ordering::Relaxed);
                    u.total_queries.fetch_add(1, Ordering::Relaxed);
                }
                Err(anyhow::anyhow!("Upstream {} failed: {}", name, e))
            }
            Err(e) => Err(anyhow::anyhow!("All upstreams failed: {}", e)),
        }
    }

    /// Send query to a single upstream and wait for response
    async fn query_upstream(query: &[u8], addr: SocketAddr, timeout: Duration) -> anyhow::Result<Vec<u8>> {
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        socket.send_to(query, addr).await?;

        let mut buf = vec![0u8; 4096];
        let len = tokio::time::timeout(timeout, socket.recv(&mut buf))
            .await
            .map_err(|_| anyhow::anyhow!("Timeout"))??;

        Ok(buf[..len].to_vec())
    }

    /// Record latency for trust scoring
    pub async fn record_latency(&self, upstream_name: &str, latency: Duration) {
        if let Some(u) = self.upstreams.iter().find(|u| u.config.name == upstream_name) {
            let mut history = u.latency_history.write();
            history.push(latency);
            // Keep last 100 entries
            if history.len() > 100 {
                let drain_to = history.len() - 100;
                history.drain(..drain_to);
            }
        }
    }

    /// Recalculate trust scores for all upstreams
    pub async fn recalculate_trust_scores(&self, min_score: f64) {
        for upstream in &self.upstreams {
            let total = upstream.total_queries.load(Ordering::Relaxed);
            let failures = upstream.total_failures.load(Ordering::Relaxed);

            if total < 10 {
                continue; // Not enough data
            }

            // Success rate component (0.0 - 1.0)
            let success_rate = 1.0 - (failures as f64 / total as f64);

            // Latency stability component
            let latency_score = {
                let history = upstream.latency_history.read();
                if history.len() < 5 {
                    1.0
                } else {
                    let avg: f64 = history.iter().map(|d| d.as_millis() as f64).sum::<f64>() / history.len() as f64;
                    let variance: f64 = history.iter()
                        .map(|d| {
                            let diff = d.as_millis() as f64 - avg;
                            diff * diff
                        })
                        .sum::<f64>() / history.len() as f64;
                    let stddev = variance.sqrt();
                    // Lower stddev = higher score
                    (1.0 - (stddev / avg).min(1.0)).max(0.0)
                }
            };

            // Combined score
            let score = success_rate * 0.7 + latency_score * 0.3;
            *upstream.trust_score.write() = score;

            // Disable if below threshold
            if score < min_score {
                *upstream.disabled.write() = true;
                warn!(
                    "Upstream {} disabled (trust score: {:.2}, threshold: {:.2})",
                    upstream.config.name, score, min_score
                );
            } else {
                *upstream.disabled.write() = false;
            }

            debug!(
                "Trust score for {}: {:.2} (success: {:.2}, latency_stability: {:.2})",
                upstream.config.name, score, success_rate, latency_score
            );
        }
    }

    fn extract_ttl(response: &[u8]) -> Option<u32> {
        let parsed = packet::parse_packet(response).ok()?;
        parsed.answers.first().map(|r| r.ttl)
    }

    /// Get upstream stats for Web UI
    pub fn get_stats(&self) -> serde_json::Value {
        let upstreams: Vec<serde_json::Value> = self.upstreams.iter().map(|u| {
            let history = u.latency_history.read();
            let avg_latency = if history.is_empty() {
                0.0
            } else {
                history.iter().map(|d| d.as_millis() as f64).sum::<f64>() / history.len() as f64
            };

            serde_json::json!({
                "name": u.config.name,
                "address": format!("{}:{}", u.config.address, u.config.port),
                "total_queries": u.total_queries.load(Ordering::Relaxed),
                "total_failures": u.total_failures.load(Ordering::Relaxed),
                "trust_score": format!("{:.2}", *u.trust_score.read()),
                "avg_latency_ms": format!("{:.1}", avg_latency),
                "disabled": *u.disabled.read(),
            })
        }).collect();

        serde_json::json!(upstreams)
    }
}

/// Select the first completed future from a vec of JoinHandles
async fn futures_select_first<T: Send + 'static>(
    tasks: Vec<tokio::task::JoinHandle<T>>,
) -> (Result<T, tokio::task::JoinError>, Vec<tokio::task::JoinHandle<T>>) {
    if tasks.is_empty() {
        panic!("No tasks to select from");
    }

    // Use futures::future::select_all equivalent with tokio
    // We convert JoinHandles to pinned futures and race them
    use std::pin::Pin;
    use std::future::Future;

    let mut futs: Vec<Pin<Box<dyn Future<Output = (usize, Result<T, tokio::task::JoinError>)> + Send>>> = 
        tasks.into_iter().enumerate().map(|(i, t)| {
            Box::pin(async move { (i, t.await) }) as Pin<Box<dyn Future<Output = _> + Send>>
        }).collect();

    // Simple approach: spawn a tokio::select on all of them
    // For now, use the fact that we can select_all via a helper
    let mut handles: Vec<tokio::task::JoinHandle<T>> = Vec::new();
    
    // Actually, the simplest correct approach:
    // Convert to a FuturesUnordered-like pattern using tokio::select with a loop
    let (tx, mut rx) = tokio::sync::mpsc::channel::<(usize, Result<T, tokio::task::JoinError>)>(1);
    
    let mut task_handles = Vec::new();
    for fut in futs {
        let tx = tx.clone();
        task_handles.push(tokio::spawn(async move {
            let (idx, result) = fut.await;
            let _ = tx.send((idx, result)).await;
        }));
    }
    drop(tx);

    let (winner_idx, result) = rx.recv().await.expect("At least one task should complete");

    // Abort remaining
    for handle in &task_handles {
        handle.abort();
    }

    (result, vec![])
}
