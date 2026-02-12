/// Prefetch module - 予測プリフェッチ
///
/// TTL切れる前に先回りで再解決する。
/// さらに時間帯別のクエリパターンを学習して、
/// 朝になったら仕事系ドメインを先に温める。
///
/// Based on RFC 8767 (Serving Stale Data) の発展形。
///
/// 主要なロジックは QueryEngine::run_prefetch_loop() と
/// CacheLayer::get_prefetch_candidates() に実装されている。
/// このモジュールは将来の時間帯パターン学習用。

use std::collections::HashMap;
use chrono::{Utc, Timelike};
use parking_lot::RwLock;

/// Time-of-day pattern learner
/// Records which domains are queried at which hours
pub struct PatternLearner {
    /// Map of hour (0-23) -> domain -> query count
    patterns: RwLock<HashMap<u8, HashMap<String, u64>>>,
    enabled: bool,
}

impl PatternLearner {
    pub fn new(enabled: bool) -> Self {
        Self {
            patterns: RwLock::new(HashMap::new()),
            enabled,
        }
    }

    /// Record a query at the current time
    pub fn record_query(&self, domain: &str) {
        if !self.enabled {
            return;
        }
        let hour = Utc::now().hour() as u8;
        let mut patterns = self.patterns.write();
        let hour_map = patterns.entry(hour).or_insert_with(HashMap::new);
        *hour_map.entry(domain.to_lowercase()).or_insert(0) += 1;
    }

    /// Get domains that should be prefetched for the given hour
    /// Returns domains sorted by frequency for that hour
    pub fn get_predictions(&self, hour: u8, top_n: usize) -> Vec<String> {
        let patterns = self.patterns.read();
        if let Some(hour_map) = patterns.get(&hour) {
            let mut sorted: Vec<_> = hour_map.iter().collect();
            sorted.sort_by(|a, b| b.1.cmp(a.1));
            sorted.into_iter()
                .take(top_n)
                .map(|(domain, _)| domain.clone())
                .collect()
        } else {
            Vec::new()
        }
    }

    /// Get stats for Web UI
    pub fn get_stats(&self) -> serde_json::Value {
        let patterns = self.patterns.read();
        let total_domains: usize = patterns.values().map(|h| h.len()).sum();
        let hours_with_data = patterns.len();
        serde_json::json!({
            "enabled": self.enabled,
            "hours_with_data": hours_with_data,
            "total_unique_domains": total_domains,
        })
    }
}
