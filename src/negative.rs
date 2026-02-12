use std::time::Instant;
use dashmap::DashMap;
use tracing::debug;

use crate::config::NegativeCacheConfig;
use crate::dns::types::RecordType;
use crate::dns::packet;

/// Negative Cache - RFC 2308 の魔改造版
///
/// NXDOMAIN をただキャッシュするだけでなく、
/// 近傍ドメイン (typoドメインの亜種) も推測してネガティブキャッシュする。
///
/// 例: "gogle.com" が NXDOMAIN → "googe.com", "googl.com" 等も
/// 事前にネガティブキャッシュに入れる (speculative mode)

#[derive(Hash, PartialEq, Eq, Clone)]
struct NegCacheKey {
    name: String,
    qtype: u16,
}

struct NegCacheEntry {
    raw_response: Vec<u8>,
    inserted_at: Instant,
    ttl: u32,
    speculative: bool,
}

pub struct NegativeCache {
    config: NegativeCacheConfig,
    entries: DashMap<NegCacheKey, NegCacheEntry>,
}

impl NegativeCache {
    pub fn new(config: &NegativeCacheConfig) -> Self {
        Self {
            config: config.clone(),
            entries: DashMap::new(),
        }
    }

    /// Check if a domain is in the negative cache
    pub fn check(&self, name: &str, qtype: &RecordType) -> Option<Vec<u8>> {
        if !self.config.enabled {
            return None;
        }

        let key = NegCacheKey {
            name: name.to_lowercase(),
            qtype: qtype.to_u16(),
        };

        if let Some(entry) = self.entries.get(&key) {
            let elapsed = entry.inserted_at.elapsed().as_secs() as u32;
            if elapsed < entry.ttl {
                return Some(entry.raw_response.clone());
            }
            // Expired
            drop(entry);
            self.entries.remove(&key);
        }

        None
    }

    /// Insert an NXDOMAIN response into the negative cache
    pub fn insert(&self, name: &str, qtype: &RecordType, response: &[u8]) {
        if !self.config.enabled {
            return;
        }

        let key = NegCacheKey {
            name: name.to_lowercase(),
            qtype: qtype.to_u16(),
        };

        // Extract SOA minimum TTL from authority section (per RFC 2308)
        let ttl = self.extract_neg_ttl(response).unwrap_or(self.config.default_ttl);

        self.entries.insert(key, NegCacheEntry {
            raw_response: response.to_vec(),
            inserted_at: Instant::now(),
            ttl,
            speculative: false,
        });

        // Speculative negative caching
        if self.config.speculative {
            self.insert_speculative(name, qtype, response, ttl);
        }
    }

    /// Generate typo variants and add to negative cache
    fn insert_speculative(&self, name: &str, qtype: &RecordType, response: &[u8], ttl: u32) {
        let variants = self.generate_typo_variants(name);
        let short_ttl = ttl.min(60); // Speculative entries get short TTL

        for variant in variants {
            let key = NegCacheKey {
                name: variant.to_lowercase(),
                qtype: qtype.to_u16(),
            };

            // Don't overwrite non-speculative entries
            if !self.entries.contains_key(&key) {
                debug!("Speculative negative cache: {} (from {})", variant, name);
                self.entries.insert(key, NegCacheEntry {
                    raw_response: response.to_vec(),
                    inserted_at: Instant::now(),
                    ttl: short_ttl,
                    speculative: true,
                });
            }
        }
    }

    /// Generate common typo variants of a domain name
    fn generate_typo_variants(&self, name: &str) -> Vec<String> {
        let mut variants = Vec::new();
        let parts: Vec<&str> = name.split('.').collect();
        
        if parts.len() < 2 {
            return variants;
        }

        let label = parts[0];
        let rest = parts[1..].join(".");

        // Character deletion: remove one character at a time
        for i in 0..label.len() {
            let mut variant = String::new();
            variant.push_str(&label[..i]);
            variant.push_str(&label[i + 1..]);
            if !variant.is_empty() {
                variants.push(format!("{}.{}", variant, rest));
            }
        }

        // Character swap: swap adjacent characters
        let chars: Vec<char> = label.chars().collect();
        for i in 0..chars.len().saturating_sub(1) {
            let mut swapped: Vec<char> = chars.clone();
            swapped.swap(i, i + 1);
            let variant: String = swapped.into_iter().collect();
            if variant != label {
                variants.push(format!("{}.{}", variant, rest));
            }
        }

        // Limit to prevent explosion
        variants.truncate(10);
        variants
    }

    /// Extract negative TTL from SOA record in authority section
    fn extract_neg_ttl(&self, response: &[u8]) -> Option<u32> {
        let parsed = packet::parse_packet(response).ok()?;
        for record in &parsed.authorities {
            if record.rtype == RecordType::SOA {
                // SOA minimum TTL is the last 4 bytes of rdata
                if record.rdata.len() >= 4 {
                    let min_ttl = u32::from_be_bytes([
                        record.rdata[record.rdata.len() - 4],
                        record.rdata[record.rdata.len() - 3],
                        record.rdata[record.rdata.len() - 2],
                        record.rdata[record.rdata.len() - 1],
                    ]);
                    return Some(min_ttl.min(record.ttl));
                }
            }
        }
        None
    }

    /// Get stats
    pub fn get_stats(&self) -> serde_json::Value {
        let total = self.entries.len();
        let speculative = self.entries.iter().filter(|e| e.speculative).count();
        serde_json::json!({
            "enabled": self.config.enabled,
            "speculative": self.config.speculative,
            "total_entries": total,
            "speculative_entries": speculative,
            "real_entries": total - speculative,
        })
    }
}
