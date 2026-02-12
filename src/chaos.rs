use crate::config::ChaosConfig;
use rand::Rng;
use std::sync::atomic::{AtomicU64, Ordering};

/// Chaos Engine - カオスエンジニアリング用の障害注入
///
/// 有効化すると、設定された確率でSERVFAILを返す。
/// 自宅ネットワークのアプリケーションがDNS障害に耐えられるかテストできる。
/// 特定のドメインを除外リストに入れることで、重要なサービスは保護可能。
pub struct ChaosEngine {
    config: ChaosConfig,
    injected_count: AtomicU64,
    checked_count: AtomicU64,
}

impl ChaosEngine {
    pub fn new(config: &ChaosConfig) -> Self {
        Self {
            config: config.clone(),
            injected_count: AtomicU64::new(0),
            checked_count: AtomicU64::new(0),
        }
    }

    /// Check if this query should fail (chaos injection)
    pub fn should_fail(&self, domain: &str) -> bool {
        if !self.config.enabled {
            return false;
        }

        self.checked_count.fetch_add(1, Ordering::Relaxed);

        // Check exclusion list
        let domain_lower = domain.to_lowercase();
        for excluded in &self.config.exclude_domains {
            if domain_lower.ends_with(&excluded.to_lowercase()) {
                return false;
            }
        }

        // Roll the dice (CSPRNG - not predictable from system state)
        let roll: f64 = {
            use rand::rngs::OsRng;
            use rand::Rng;
            OsRng.gen()
        };
        if roll < self.config.servfail_probability {
            self.injected_count.fetch_add(1, Ordering::Relaxed);
            true
        } else {
            false
        }
    }

    pub fn get_stats(&self) -> serde_json::Value {
        serde_json::json!({
            "enabled": self.config.enabled,
            "probability": self.config.servfail_probability,
            "total_checked": self.checked_count.load(Ordering::Relaxed),
            "total_injected": self.injected_count.load(Ordering::Relaxed),
            "excluded_domains": self.config.exclude_domains,
        })
    }
}
