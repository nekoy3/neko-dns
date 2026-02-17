use std::sync::Arc;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::{TcpStream, UdpSocket};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{info, debug, warn};

use crate::config::Config;
use crate::cache::CacheLayer;
use crate::upstream::UpstreamManager;
use crate::chaos::ChaosEngine;
use crate::journal::Journal;
use crate::dns::packet;
use crate::dns::types::RecordType;
use crate::edns::EdnsHandler;
use crate::negative::NegativeCache;
use crate::neko_comment::{NekoComment, QueryFeatures};
use crate::recursive::RecursiveResolver;
use crate::journey::JourneyTracker;
use crate::curiosity::CuriosityCache;
use crate::metrics::MetricsCounters;

/// Core query engine - handles all DNS query processing
pub struct QueryEngine {
    pub config: Arc<Config>,
    pub cache: Arc<CacheLayer>,
    pub upstream: Arc<UpstreamManager>,
    pub chaos: Arc<ChaosEngine>,
    pub journal: Arc<Journal>,
    pub edns: Arc<EdnsHandler>,
    pub negative: Arc<NegativeCache>,
    pub neko_comment: Arc<NekoComment>,
    pub recursive: Option<Arc<RecursiveResolver>>,
    pub journey: Arc<JourneyTracker>,
    pub curiosity: Arc<CuriosityCache>,
    pub metrics: Arc<MetricsCounters>,
}

impl QueryEngine {
    pub async fn new(config: Arc<Config>) -> anyhow::Result<Self> {
        let cache = Arc::new(CacheLayer::new(&config.cache, &config.ttl_alchemy));
        let upstream = Arc::new(UpstreamManager::new(&config.upstreams).await?);
        let chaos = Arc::new(ChaosEngine::new(&config.chaos));
        let journal = Arc::new(Journal::new(&config.journal)?);
        let edns = Arc::new(EdnsHandler::new(&config.edns));
        let negative = Arc::new(NegativeCache::new(&config.negative));
        let neko_comment = Arc::new(NekoComment::new(&config.neko_comment));

        // 再帰解決エンジン (有効な場合のみ初期化)
        let recursive = if config.recursive.enabled {
            match RecursiveResolver::new(&config.recursive) {
                Ok(r) => {
                    info!("🌲 Recursive resolution enabled (parallel DFS, {} branches)", config.recursive.parallel_branches);
                    Some(Arc::new(r))
                }
                Err(e) => {
                    warn!("🌲 Failed to init recursive resolver: {} (falling back to forwarding)", e);
                    None
                }
            }
        } else {
            info!("📡 Forwarding mode (recursive resolution disabled)");
            None
        };

        let journey = Arc::new(JourneyTracker::new(config.recursive.journey_txt));
        let curiosity = Arc::new(CuriosityCache::new(config.recursive.glue_ttl_secs));

        // ローカルゾーン情報をログ出力
        if !config.local_zones.is_empty() {
            for zone in &config.local_zones {
                info!("🏠 Local zone: *.{} -> {}:{}", zone.domain, zone.server, zone.port);
            }
        }

        let metrics = Arc::new(MetricsCounters::new());

        Ok(Self {
            config,
            cache,
            upstream,
            chaos,
            journal,
            edns,
            negative,
            neko_comment,
            recursive,
            journey,
            curiosity,
            metrics,
        })
    }

    /// Handle a raw DNS query and return raw response bytes
    pub async fn handle_query(&self, query_data: &[u8]) -> anyhow::Result<Vec<u8>> {
        let start = std::time::Instant::now();
        let mut features = QueryFeatures::new();

        // Parse the incoming query
        let (qname, qtype) = packet::extract_query_info(query_data)?;
        debug!("Query: {} {}", qname, qtype.name());

        // 📊 Metrics: count query
        self.metrics.queries_total.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.metrics.inc_query_type(&qtype.name());

        // Check chaos mode - maybe inject a failure
        if self.chaos.should_fail(&qname) {
            info!("🎲 Chaos mode: injecting SERVFAIL for {}", qname);
            features.chaos_triggered = true;
            self.metrics.servfail_total.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            self.journal.record_query(&qname, &qtype, "CHAOS_SERVFAIL", 0, start.elapsed()).await;
            let mut response = packet::build_servfail(query_data)?;
            features.latency_ms = Some(start.elapsed().as_millis() as u64);
            packet::append_feature_record(&mut response, &self.neko_comment, &features);
            return Ok(response);
        }

        // Check EDNS custom options in query
        let edns_meta = self.edns.extract_options(query_data);
        if let Some(ref meta) = edns_meta {
            debug!("EDNS custom metadata: {:?}", meta);
            features.edns_detected = true;
        }

        // Check negative cache
        if let Some(neg_response) = self.negative.check(&qname, &qtype) {
            debug!("Negative cache hit: {} {}", qname, qtype.name());
            features.negative_cache_hit = true;
            self.metrics.negative_cache_hits.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            self.metrics.cache_hits.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            self.metrics.nxdomain_total.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            features.latency_ms = Some(start.elapsed().as_millis() as u64);
            let mut response = neg_response;
            packet::append_feature_record(&mut response, &self.neko_comment, &features);
            self.journal.record_query(&qname, &qtype, "NEGATIVE_CACHE_HIT", 0, start.elapsed()).await;
            return Ok(response);
        }

        // Check cache
        if let Some(cached) = self.cache.get(&qname, &qtype).await {
            debug!("Cache hit: {} {} (remaining TTL: {}s)", qname, qtype.name(), cached.remaining_ttl);
            features.cache_hit = true;
            features.ttl_alchemy = true;
            self.metrics.cache_hits.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            self.metrics.noerror_total.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            features.latency_ms = Some(start.elapsed().as_millis() as u64);
            let mut response = packet::build_response(query_data, &cached.raw_response, cached.remaining_ttl)?;
            // 🐱 Feature notification
            packet::append_feature_record(&mut response, &self.neko_comment, &features);
            self.journal.record_query(&qname, &qtype, &cached.upstream_name, cached.remaining_ttl, start.elapsed()).await;

            // Record hit for prefetch/TTL alchemy
            self.cache.record_hit(&qname, &qtype).await;

            return Ok(response);
        }

        // Cache miss - try local zone forwarding, recursive resolution, or upstream forwarding
        debug!("Cache miss: {} {} - resolving", qname, qtype.name());
        features.cache_miss = true;
        self.metrics.cache_misses.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        // 🏠 Check local zones first
        let local_zone_result = self.try_local_zone_forward(query_data, &qname).await;

        let (result_response, result_upstream_name, result_latency, result_original_ttl) = 
            if let Some((response, latency)) = local_zone_result {
                // ローカルドメイン転送成功
                features.local_zone = true;
                self.metrics.local_zone_queries.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let ttl = packet::parse_packet(&response)
                    .ok()
                    .and_then(|p| p.answers.first().map(|a| a.ttl))
                    .unwrap_or(0);
                (response, "local-zone".to_string(), latency, ttl)
            } else if let Some(ref recursive) = self.recursive {
                // 🌲 再帰解決モード
                features.recursive = true;
                features.parallel_dfs = true;
                self.metrics.recursive_queries.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let start_resolve = std::time::Instant::now();
                match recursive.resolve(&qname, qtype, &self.curiosity, &self.journey).await {
                    Ok(mut response) => {
                        let latency = start_resolve.elapsed();
                        self.metrics.recursive_successes.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        self.metrics.record_recursive_latency(latency.as_micros() as u64);
                        let ttl = packet::parse_packet(&response)
                            .ok()
                            .and_then(|p| p.answers.first().map(|a| a.ttl))
                            .unwrap_or(0);
                        // 元クエリのトランザクションIDをコピー
                        if response.len() >= 12 && query_data.len() >= 2 {
                            response[0] = query_data[0];
                            response[1] = query_data[1];
                            // RA=1 (Recursion Available) を設定
                            response[3] |= 0x80;
                        }
                        features.journey_recorded = true;
                        (response, "recursive".to_string(), latency, ttl)
                    }
                    Err(e) => {
                        warn!("🌲 Recursive resolution failed for {} {}: {}, falling back to upstream", qname, qtype.name(), e);
                        self.metrics.recursive_failures.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        // フォールバック: upstream forwarding
                        features.recursive = false;
                        features.upstream_forward = true;
                        self.metrics.upstream_queries.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        let result = self.upstream.race_query(query_data).await?;
                        features.upstream_winner = Some(result.upstream_name.clone());
                        (result.response, result.upstream_name, result.latency, result.original_ttl)
                    }
                }
            } else {
                // 📡 フォワーディングモード
                features.upstream_forward = true;
                self.metrics.upstream_queries.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let result = self.upstream.race_query(query_data).await?;
                features.upstream_winner = Some(result.upstream_name.clone());
                (result.response, result.upstream_name, result.latency, result.original_ttl)
            };

        // Parse response for caching
        let response_packet = packet::parse_packet(&result_response)?;

        // Check if NXDOMAIN - add to negative cache
        if response_packet.header.rcode == crate::dns::types::ResponseCode::NxDomain {
            self.negative.insert(&qname, &qtype, &result_response);
            self.metrics.nxdomain_total.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            debug!("Cached negative response for {} {}", qname, qtype.name());
        }

        // Cache the response (TTL alchemy will be applied internally)
        if response_packet.header.rcode == crate::dns::types::ResponseCode::NoError {
            self.metrics.noerror_total.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            self.cache.insert(&qname, &qtype, &result_response, &result_upstream_name).await;
        } else if response_packet.header.rcode == crate::dns::types::ResponseCode::ServFail {
            self.metrics.servfail_total.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }

        // Record in journal
        self.journal.record_query(
            &qname,
            &qtype,
            &result_upstream_name,
            result_original_ttl,
            start.elapsed(),
        ).await;

        // Update upstream latency for trust scoring (forwarding mode only)
        if result_upstream_name != "recursive" {
            self.upstream.record_latency(&result_upstream_name, result_latency).await;
        }

        info!(
            "{} {} -> {} (via: {}, latency: {:?})",
            qname, qtype.name(), 
            if response_packet.header.ancount > 0 { "OK" } else { "EMPTY" },
            result_upstream_name,
            result_latency
        );

        // 🐱 Feature notification (ASCII-only, shows triggered features)
        let mut response = result_response;
        features.latency_ms = Some(start.elapsed().as_millis() as u64);
        packet::append_feature_record(&mut response, &self.neko_comment, &features);

        // 🗺️ Resolution Journey TXT (recursive mode only)
        if self.recursive.is_some() {
            if let Some(journey_txt) = self.journey.build_journey_txt(&qname) {
                let arcount = u16::from_be_bytes([response[10], response[11]]);
                let new_arcount = arcount.wrapping_add(1);
                let ar_bytes = new_arcount.to_be_bytes();
                response[10] = ar_bytes[0];
                response[11] = ar_bytes[1];
                response.extend_from_slice(&journey_txt);
            }
        }

        Ok(response)
    }

    /// Handle TCP DNS queries (length-prefixed)
    pub async fn handle_tcp(&self, mut stream: TcpStream, addr: SocketAddr) -> anyhow::Result<()> {
        debug!("TCP connection from {}", addr);
        self.metrics.tcp_queries.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        loop {
            // Read 2-byte length prefix
            let mut len_buf = [0u8; 2];
            match stream.read_exact(&mut len_buf).await {
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(e.into()),
            }
            let msg_len = u16::from_be_bytes(len_buf) as usize;

            if msg_len == 0 || msg_len > 65535 {
                break;
            }

            // Read message
            let mut msg_buf = vec![0u8; msg_len];
            stream.read_exact(&mut msg_buf).await?;

            // Process query
            let response = match self.handle_query(&msg_buf).await {
                Ok(r) => r,
                Err(_) => packet::build_servfail(&msg_buf)?,
            };

            // Send response with length prefix
            let resp_len = (response.len() as u16).to_be_bytes();
            stream.write_all(&resp_len).await?;
            stream.write_all(&response).await?;
        }

        Ok(())
    }

    /// Prefetch loop - periodically check for entries nearing expiry
    pub async fn run_prefetch_loop(&self) {
        if !self.config.prefetch.enabled {
            return;
        }

        let interval = std::time::Duration::from_secs(self.config.prefetch.check_interval_secs);
        info!("Prefetch loop started (interval: {:?})", interval);

        loop {
            tokio::time::sleep(interval).await;
            let candidates = self.cache.get_prefetch_candidates(
                self.config.prefetch.threshold_ratio,
            ).await;

            for (name, qtype) in candidates {
                debug!("Prefetching: {} {}", name, qtype.name());
                // Use handle_query so recursive mode is respected
                let query = packet::build_query({ use rand::rngs::OsRng; use rand::Rng; OsRng.gen() }, &name, qtype, true);
                let _ = self.handle_query(&query).await;
            }
        }
    }

    /// Trust scorer loop - periodically recalculate upstream trust scores
    pub async fn run_trust_scorer(&self) {
        if !self.config.trust.enabled {
            return;
        }

        let interval = std::time::Duration::from_secs(self.config.trust.recalc_interval_secs);
        info!("Trust scorer started (interval: {:?})", interval);

        loop {
            tokio::time::sleep(interval).await;
            self.upstream.recalculate_trust_scores(self.config.trust.min_score).await;
        }
    }

    /// Get stats for Web UI
    pub fn get_stats(&self) -> serde_json::Value {
        let mut stats = serde_json::json!({
            "cache": self.cache.get_stats(),
            "upstreams": self.upstream.get_stats(),
            "journal": self.journal.get_stats(),
            "chaos": self.chaos.get_stats(),
            "negative_cache": self.negative.get_stats(),
            "journey": self.journey.get_stats(),
            "curiosity": self.curiosity.get_stats(),
        });

        if let Some(ref recursive) = self.recursive {
            stats["recursive"] = recursive.get_stats();
            stats["mode"] = serde_json::json!("recursive");
        } else {
            stats["mode"] = serde_json::json!("forwarding");
        }

        if !self.config.local_zones.is_empty() {
            let zones: Vec<serde_json::Value> = self.config.local_zones.iter().map(|z| {
                serde_json::json!({ "domain": z.domain, "server": format!("{}:{}", z.server, z.port) })
            }).collect();
            stats["local_zones"] = serde_json::json!(zones);
        }

        stats
    }

    /// 好奇心散歩ループ - バックグラウンドで散歩キューを処理
    pub async fn run_curiosity_walk_loop(&self) {
        if !self.config.recursive.enabled || !self.config.recursive.curiosity_walk {
            return;
        }

        info!("🐱 Curiosity walk loop started");
        let interval = std::time::Duration::from_secs(5);

        loop {
            tokio::time::sleep(interval).await;

            // 散歩キューからターゲットを取得して解決
            while let Some(target) = self.curiosity.pop_walk_target() {
                if self.cache.get(&target, &RecordType::A).await.is_none() {
                    debug!("🐱 Curiosity walk: resolving {}", target);
                    let query = packet::build_query({ use rand::rngs::OsRng; use rand::Rng; OsRng.gen() }, &target, RecordType::A, true);
                    let _ = self.handle_query(&query).await;
                }
            }

            // 定期クリーンアップ
            self.curiosity.cleanup();
        }
    }

    /// 🏠 ローカルゾーン転送: ドメインがローカルゾーンにマッチする場合、指定サーバーに転送
    async fn try_local_zone_forward(&self, query_data: &[u8], qname: &str) -> Option<(Vec<u8>, Duration)> {
        let qname_lower = qname.to_lowercase();

        for zone in &self.config.local_zones {
            let domain_suffix = zone.domain.to_lowercase();
            // "mynk.home" matches "foo.mynk.home" and "mynk.home" itself
            if qname_lower == domain_suffix || qname_lower.ends_with(&format!(".{}", domain_suffix)) {
                debug!("🏠 Local zone match: {} -> {}:{}", qname, zone.server, zone.port);

                let addr: SocketAddr = match format!("{}:{}", zone.server, zone.port).parse() {
                    Ok(a) => a,
                    Err(e) => {
                        warn!("🏠 Invalid local zone server address {}:{}: {}", zone.server, zone.port, e);
                        return None;
                    }
                };

                let timeout = Duration::from_millis(zone.timeout_ms);
                let start = std::time::Instant::now();

                match Self::query_local_zone(query_data, addr, timeout).await {
                    Ok(mut response) => {
                        let latency = start.elapsed();
                        // 元クエリのトランザクションIDをコピー
                        if response.len() >= 2 && query_data.len() >= 2 {
                            response[0] = query_data[0];
                            response[1] = query_data[1];
                        }
                        // RA=1 (Recursion Available) を設定
                        if response.len() >= 4 {
                            response[3] |= 0x80;
                        }
                        info!("🏠 Local zone {} -> {}:{} ({:.1}ms)", qname, zone.server, zone.port, latency.as_millis());
                        return Some((response, latency));
                    }
                    Err(e) => {
                        warn!("🏠 Local zone query failed for {} -> {}:{}: {}", qname, zone.server, zone.port, e);
                        return None;
                    }
                }
            }
        }

        None
    }

    /// ローカルゾーンサーバーへの単純UDP転送
    async fn query_local_zone(query: &[u8], addr: SocketAddr, timeout: Duration) -> anyhow::Result<Vec<u8>> {
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        socket.send_to(query, addr).await?;

        let mut buf = vec![0u8; 4096];
        let len = tokio::time::timeout(timeout, socket.recv(&mut buf))
            .await
            .map_err(|_| anyhow::anyhow!("Timeout querying local zone {}", addr))??;

        Ok(buf[..len].to_vec())
    }

    /// ジャーニー履歴取得 (API用)
    pub fn get_journey_history(&self, limit: usize) -> Vec<serde_json::Value> {
        self.journey.get_history(limit)
    }
}
