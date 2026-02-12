use crate::config::NekoCommentConfig;

/// 🐱 neko-dns feature notifier
/// Adds an ADDITIONAL TXT record showing which resolver features
/// were triggered during query processing.
/// All messages are pure ASCII to avoid encoding issues in dig/drill output.

pub struct NekoComment {
    enabled: bool,
}

/// Tracks which features were triggered during a single query processing
#[derive(Debug, Clone, Default)]
pub struct QueryFeatures {
    pub cache_hit: bool,
    pub cache_miss: bool,
    pub ttl_alchemy: bool,
    pub recursive: bool,
    pub upstream_forward: bool,
    pub negative_cache_hit: bool,
    pub serve_stale: bool,
    pub prefetch_candidate: bool,
    pub curiosity_glue_hit: bool,
    pub journey_recorded: bool,
    pub parallel_dfs: bool,
    pub edns_detected: bool,
    pub chaos_triggered: bool,
    /// Which upstream won the race (if forwarding mode)
    pub upstream_winner: Option<String>,
    /// Resolution latency in ms
    pub latency_ms: Option<u64>,
}

impl QueryFeatures {
    pub fn new() -> Self {
        Self::default()
    }

    /// Build a compact ASCII summary of triggered features
    pub fn to_summary(&self) -> String {
        let mut tags: Vec<&str> = Vec::new();

        if self.cache_hit      { tags.push("CACHE_HIT"); }
        if self.cache_miss     { tags.push("CACHE_MISS"); }
        if self.recursive      { tags.push("RECURSIVE"); }
        if self.parallel_dfs   { tags.push("DFS_PARALLEL"); }
        if self.upstream_forward { tags.push("FORWARDED"); }
        if self.negative_cache_hit { tags.push("NEG_CACHE"); }
        if self.serve_stale    { tags.push("SERVE_STALE"); }
        if self.ttl_alchemy    { tags.push("TTL_ALCHEMY"); }
        if self.curiosity_glue_hit { tags.push("CURIOSITY_GLUE"); }
        if self.journey_recorded { tags.push("JOURNEY"); }
        if self.edns_detected  { tags.push("EDNS"); }
        if self.chaos_triggered { tags.push("CHAOS"); }

        let features = tags.join("|");
        let mut parts = vec![format!("neko-dns [{}]", features)];

        if let Some(ref name) = self.upstream_winner {
            parts.push(format!("via:{}", name));
        }
        if let Some(ms) = self.latency_ms {
            parts.push(format!("{}ms", ms));
        }

        parts.join(" ")
    }
}

impl NekoComment {
    pub fn new(config: &NekoCommentConfig) -> Self {
        Self {
            enabled: config.enabled,
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Build an ADDITIONAL TXT record from triggered query features.
    /// name: "neko-dns.features." TXT record, class CH, TTL 0
    /// All content is pure ASCII - no encoding issues with any DNS client.
    pub fn build_feature_txt(&self, features: &QueryFeatures) -> Option<Vec<u8>> {
        if !self.enabled {
            return None;
        }

        let summary = features.to_summary();
        let summary_bytes = summary.as_bytes();

        // Sanity: TXT RDATA must fit reasonably in a DNS packet
        if summary_bytes.len() > 500 {
            return None;
        }

        let mut record = Vec::new();

        // Name: "neko-dns.features." encoded as DNS labels
        record.push(8);
        record.extend_from_slice(b"neko-dns");
        record.push(8);
        record.extend_from_slice(b"features");
        record.push(0); // root label

        // Type: TXT (16)
        record.extend_from_slice(&16u16.to_be_bytes());
        // Class: IN (1) - use IN class for maximum client compatibility
        record.extend_from_slice(&1u16.to_be_bytes());
        // TTL: 0 (do not cache)
        record.extend_from_slice(&0u32.to_be_bytes());

        // RDATA: TXT format = length-prefixed character-strings (max 255 each)
        let mut rdata = Vec::new();
        for chunk in summary_bytes.chunks(255) {
            rdata.push(chunk.len() as u8);
            rdata.extend_from_slice(chunk);
        }

        // RDLENGTH
        record.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        record.extend(rdata);

        Some(record)
    }
}
