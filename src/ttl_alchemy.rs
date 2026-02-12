use crate::config::TtlAlchemyConfig;

/// TTL Alchemy Engine
/// RFC 2308 + 独自拡張: クエリ頻度と応答の変動率から動的にTTLを再計算する
///
/// - よくクエリされるドメイン → TTL延長 (キャッシュ効率向上)
/// - 応答が頻繁に変わるドメイン → TTL短縮 (鮮度重視)
/// - 時間帯による変動なし → 安定ドメインとしてTTL大幅延長
pub struct TtlAlchemy {
    config: TtlAlchemyConfig,
}

impl TtlAlchemy {
    pub fn new(config: &TtlAlchemyConfig) -> Self {
        Self {
            config: config.clone(),
        }
    }

    /// Calculate a new TTL based on original TTL, query frequency, and response volatility
    ///
    /// Formula:
    ///   frequency_factor = log2(1 + hit_count) * frequency_weight
    ///   volatility_factor = rdata_changes * volatility_weight
    ///   alchemized_ttl = original_ttl * (1 + frequency_factor) / (1 + volatility_factor)
    ///   result = clamp(alchemized_ttl, min_ttl, max_ttl)
    pub fn calculate_ttl(&self, original_ttl: u32, hit_count: u64, rdata_changes: u32) -> u32 {
        if !self.config.enabled {
            return original_ttl.clamp(self.config.min_ttl, self.config.max_ttl);
        }

        let freq_factor = (1.0 + hit_count as f64).log2() * self.config.frequency_weight;
        let vol_factor = rdata_changes as f64 * self.config.volatility_weight;

        let alchemized = original_ttl as f64 * (1.0 + freq_factor) / (1.0 + vol_factor);
        let result = alchemized.round() as u32;

        result.clamp(self.config.min_ttl, self.config.max_ttl)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> TtlAlchemyConfig {
        TtlAlchemyConfig {
            enabled: true,
            min_ttl: 30,
            max_ttl: 86400,
            frequency_weight: 0.3,
            volatility_weight: 0.5,
        }
    }

    #[test]
    fn test_no_hits_no_changes() {
        let alchemy = TtlAlchemy::new(&test_config());
        // With 0 hits and 0 changes, TTL should be close to original
        let result = alchemy.calculate_ttl(300, 0, 0);
        assert_eq!(result, 300);
    }

    #[test]
    fn test_high_frequency_extends_ttl() {
        let alchemy = TtlAlchemy::new(&test_config());
        // 1000 hits should significantly extend TTL
        let result = alchemy.calculate_ttl(300, 1000, 0);
        assert!(result > 300, "TTL should be extended: got {}", result);
    }

    #[test]
    fn test_high_volatility_shortens_ttl() {
        let alchemy = TtlAlchemy::new(&test_config());
        // 10 rdata changes should shorten TTL
        let result = alchemy.calculate_ttl(300, 0, 10);
        assert!(result < 300, "TTL should be shortened: got {}", result);
    }

    #[test]
    fn test_ttl_clamped() {
        let alchemy = TtlAlchemy::new(&test_config());
        // Very high volatility shouldn't go below min
        let result = alchemy.calculate_ttl(300, 0, 1000);
        assert!(result >= 30, "TTL should not go below min_ttl: got {}", result);
        
        // Very high frequency shouldn't go above max
        let result = alchemy.calculate_ttl(86400, 1_000_000, 0);
        assert!(result <= 86400, "TTL should not exceed max_ttl: got {}", result);
    }

    #[test]
    fn test_disabled_returns_clamped_original() {
        let mut config = test_config();
        config.enabled = false;
        let alchemy = TtlAlchemy::new(&config);
        let result = alchemy.calculate_ttl(300, 1000, 0);
        assert_eq!(result, 300);
    }
}
