use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use chrono::Utc;
use parking_lot::RwLock;
use tracing::debug;

use crate::config::JournalConfig;
use crate::dns::types::RecordType;

/// Query Journal - 全クエリ/応答をWAL的に記録
///
/// 「昨日の23時にこのドメインは何に解決されてた？」が引ける。
/// タイムトラベルデバッグに最適。
#[derive(Debug, Clone, serde::Serialize)]
pub struct JournalEntry {
    pub timestamp: String,
    pub domain: String,
    pub qtype: String,
    pub upstream: String,
    pub ttl: u32,
    pub latency_us: u64,
}

pub struct Journal {
    config: JournalConfig,
    entries: RwLock<Vec<JournalEntry>>,
    total_recorded: AtomicU64,
}

impl Journal {
    pub fn new(config: &JournalConfig) -> anyhow::Result<Self> {
        Ok(Self {
            config: config.clone(),
            entries: RwLock::new(Vec::new()),
            total_recorded: AtomicU64::new(0),
        })
    }

    /// Record a query in the journal
    pub async fn record_query(
        &self,
        domain: &str,
        qtype: &RecordType,
        upstream: &str,
        ttl: u32,
        latency: Duration,
    ) {
        if !self.config.enabled {
            return;
        }

        let entry = JournalEntry {
            timestamp: Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string(),
            domain: domain.to_string(),
            qtype: qtype.name(),
            upstream: upstream.to_string(),
            ttl,
            latency_us: latency.as_micros() as u64,
        };

        let mut entries = self.entries.write();
        entries.push(entry);
        self.total_recorded.fetch_add(1, Ordering::Relaxed);

        // Rotation: keep within max_entries
        if entries.len() > self.config.max_entries {
            let drain_count = entries.len() - self.config.max_entries;
            entries.drain(..drain_count);
        }
    }

    /// Query the journal - search by domain and optional time range
    pub fn search(
        &self,
        domain: Option<&str>,
        qtype: Option<&str>,
        limit: usize,
    ) -> Vec<JournalEntry> {
        let entries = self.entries.read();
        entries.iter()
            .rev() // Most recent first
            .filter(|e| {
                if let Some(d) = domain {
                    if !e.domain.contains(d) {
                        return false;
                    }
                }
                if let Some(qt) = qtype {
                    if e.qtype != qt {
                        return false;
                    }
                }
                true
            })
            .take(limit)
            .cloned()
            .collect()
    }

    /// Get recent entries for Web UI
    pub fn recent(&self, count: usize) -> Vec<JournalEntry> {
        let entries = self.entries.read();
        entries.iter().rev().take(count).cloned().collect()
    }

    /// Get journal stats
    pub fn get_stats(&self) -> serde_json::Value {
        let entries = self.entries.read();
        serde_json::json!({
            "enabled": self.config.enabled,
            "current_entries": entries.len(),
            "max_entries": self.config.max_entries,
            "total_recorded": self.total_recorded.load(Ordering::Relaxed),
        })
    }
}
