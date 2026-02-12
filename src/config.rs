use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    pub listen: ListenConfig,
    pub upstreams: Vec<UpstreamConfig>,
    pub cache: CacheConfig,
    pub ttl_alchemy: TtlAlchemyConfig,
    pub prefetch: PrefetchConfig,
    pub trust: TrustConfig,
    pub chaos: ChaosConfig,
    pub journal: JournalConfig,
    pub negative: NegativeCacheConfig,
    pub edns: EdnsConfig,
    pub web: WebConfig,
    #[serde(default)]
    pub neko_comment: NekoCommentConfig,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ListenConfig {
    pub address: String,
    pub port: u16,
}

#[derive(Debug, Deserialize, Clone)]
pub struct UpstreamConfig {
    pub name: String,
    pub address: String,
    pub port: u16,
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
}

#[derive(Debug, Deserialize, Clone)]
pub struct CacheConfig {
    #[serde(default = "default_max_entries")]
    pub max_entries: usize,
    #[serde(default)]
    pub serve_stale: bool,
    #[serde(default = "default_stale_ttl")]
    pub stale_ttl_secs: u64,
}

#[derive(Debug, Deserialize, Clone)]
pub struct TtlAlchemyConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_min_ttl")]
    pub min_ttl: u32,
    #[serde(default = "default_max_ttl")]
    pub max_ttl: u32,
    /// Frequency weight: how much query frequency affects TTL extension
    #[serde(default = "default_freq_weight")]
    pub frequency_weight: f64,
    /// Volatility weight: how much response changes shorten TTL
    #[serde(default = "default_vol_weight")]
    pub volatility_weight: f64,
}

#[derive(Debug, Deserialize, Clone)]
pub struct PrefetchConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Prefetch when TTL remaining is below this ratio (e.g., 0.1 = 10% of original TTL)
    #[serde(default = "default_prefetch_threshold")]
    pub threshold_ratio: f64,
    /// Enable time-of-day pattern learning
    #[serde(default)]
    pub learn_patterns: bool,
    #[serde(default = "default_prefetch_interval")]
    pub check_interval_secs: u64,
}

#[derive(Debug, Deserialize, Clone)]
pub struct TrustConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Minimum trust score to keep using an upstream (0.0 - 1.0)
    #[serde(default = "default_trust_threshold")]
    pub min_score: f64,
    /// How often to recalculate trust scores
    #[serde(default = "default_trust_interval")]
    pub recalc_interval_secs: u64,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ChaosConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Probability of injecting a SERVFAIL (0.0 - 1.0)
    #[serde(default = "default_chaos_probability")]
    pub servfail_probability: f64,
    /// Domains to exclude from chaos mode
    #[serde(default)]
    pub exclude_domains: Vec<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct JournalConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub path: Option<String>,
    /// Max journal entries before rotation
    #[serde(default = "default_journal_max")]
    pub max_entries: usize,
    /// Retention period in hours
    #[serde(default = "default_journal_retention")]
    pub retention_hours: u64,
}

#[derive(Debug, Deserialize, Clone)]
pub struct NegativeCacheConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Enable speculative negative caching for typo-like domains
    #[serde(default)]
    pub speculative: bool,
    #[serde(default = "default_neg_ttl")]
    pub default_ttl: u32,
}

#[derive(Debug, Deserialize, Clone)]
pub struct EdnsConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Custom EDNS option code (65001-65534 range for private use)
    #[serde(default = "default_edns_code")]
    pub custom_option_code: u16,
}

#[derive(Debug, Deserialize, Clone)]
pub struct WebConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_web_address")]
    pub address: String,
    #[serde(default = "default_web_port")]
    pub port: u16,
}

#[derive(Debug, Deserialize, Clone)]
pub struct NekoCommentConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
}

impl Default for NekoCommentConfig {
    fn default() -> Self {
        Self { enabled: true }
    }
}

// Default value functions
fn default_timeout_ms() -> u64 { 2000 }
fn default_max_entries() -> usize { 100_000 }
fn default_stale_ttl() -> u64 { 86400 }
fn default_true() -> bool { true }
fn default_min_ttl() -> u32 { 30 }
fn default_max_ttl() -> u32 { 86400 }
fn default_freq_weight() -> f64 { 0.3 }
fn default_vol_weight() -> f64 { 0.5 }
fn default_prefetch_threshold() -> f64 { 0.1 }
fn default_prefetch_interval() -> u64 { 10 }
fn default_trust_threshold() -> f64 { 0.5 }
fn default_trust_interval() -> u64 { 60 }
fn default_chaos_probability() -> f64 { 0.01 }
fn default_journal_max() -> usize { 1_000_000 }
fn default_journal_retention() -> u64 { 168 }
fn default_neg_ttl() -> u32 { 300 }
fn default_edns_code() -> u16 { 65001 }
fn default_web_address() -> String { "0.0.0.0".to_string() }
fn default_web_port() -> u16 { 8053 }

impl Config {
    pub fn load(path: &str) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("Failed to read config file '{}': {}", path, e))?;
        let config: Config = toml::from_str(&content)
            .map_err(|e| anyhow::anyhow!("Failed to parse config '{}': {}", path, e))?;
        Ok(config)
    }
}
