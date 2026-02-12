use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use dashmap::DashMap;
use tracing::debug;

use crate::config::{CacheConfig, TtlAlchemyConfig};
use crate::dns::types::RecordType;
use crate::dns::packet;
use crate::ttl_alchemy::TtlAlchemy;

/// Cache key: (domain name, record type)
#[derive(Hash, PartialEq, Eq, Clone, Debug)]
pub struct CacheKey {
    pub name: String,
    pub qtype: u16,
}

/// Cached entry with metadata
#[derive(Clone, Debug)]
pub struct CacheEntry {
    pub raw_response: Vec<u8>,
    pub original_ttl: u32,
    pub alchemized_ttl: u32,
    pub inserted_at: Instant,
    pub upstream_name: String,
    pub hit_count: u64,
    pub last_rdata_hash: u64,  // Hash of rdata for volatility detection
    pub rdata_changes: u32,    // How many times rdata changed
}

/// Cache lookup result
pub struct CacheLookup {
    pub raw_response: Vec<u8>,
    pub remaining_ttl: u32,
    pub upstream_name: String,
}

pub struct CacheLayer {
    entries: DashMap<CacheKey, CacheEntry>,
    config: CacheConfig,
    alchemy: TtlAlchemy,
    // Stats
    hits: AtomicU64,
    misses: AtomicU64,
    evictions: AtomicU64,
}

impl CacheLayer {
    pub fn new(config: &CacheConfig, alchemy_config: &TtlAlchemyConfig) -> Self {
        Self {
            entries: DashMap::new(),
            config: config.clone(),
            alchemy: TtlAlchemy::new(alchemy_config),
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            evictions: AtomicU64::new(0),
        }
    }

    /// Look up a cached entry
    pub async fn get(&self, name: &str, qtype: &RecordType) -> Option<CacheLookup> {
        let key = CacheKey {
            name: name.to_lowercase(),
            qtype: qtype.to_u16(),
        };

        if let Some(entry) = self.entries.get(&key) {
            let elapsed = entry.inserted_at.elapsed().as_secs() as u32;
            let ttl = entry.alchemized_ttl;

            if elapsed < ttl {
                self.hits.fetch_add(1, Ordering::Relaxed);
                return Some(CacheLookup {
                    raw_response: entry.raw_response.clone(),
                    remaining_ttl: ttl - elapsed,
                    upstream_name: entry.upstream_name.clone(),
                });
            }

            // TTL expired - check serve-stale
            if self.config.serve_stale {
                let stale_elapsed = elapsed as u64 - ttl as u64;
                if stale_elapsed < self.config.stale_ttl_secs {
                    debug!("Serving stale entry for {} {} (stale for {}s)", name, qtype.name(), stale_elapsed);
                    self.hits.fetch_add(1, Ordering::Relaxed);
                    return Some(CacheLookup {
                        raw_response: entry.raw_response.clone(),
                        remaining_ttl: 1, // Minimal TTL for stale
                        upstream_name: format!("{} (stale)", entry.upstream_name),
                    });
                }
            }
        }

        self.misses.fetch_add(1, Ordering::Relaxed);
        None
    }

    /// Insert a new entry
    pub async fn insert(&self, name: &str, qtype: &RecordType, response: &[u8], upstream_name: &str) {
        // Extract TTL from response
        let original_ttl = self.extract_min_ttl(response).unwrap_or(300);

        let key = CacheKey {
            name: name.to_lowercase(),
            qtype: qtype.to_u16(),
        };

        // Calculate rdata hash for volatility tracking
        let rdata_hash = self.hash_rdata(response);

        // Check if entry exists (for volatility tracking)
        let (rdata_changes, hit_count) = if let Some(existing) = self.entries.get(&key) {
            let changes = if existing.last_rdata_hash != rdata_hash {
                existing.rdata_changes + 1
            } else {
                existing.rdata_changes
            };
            (changes, existing.hit_count)
        } else {
            (0, 0)
        };

        // Apply TTL alchemy
        let alchemized_ttl = self.alchemy.calculate_ttl(
            original_ttl,
            hit_count,
            rdata_changes,
        );

        let entry = CacheEntry {
            raw_response: response.to_vec(),
            original_ttl,
            alchemized_ttl,
            inserted_at: Instant::now(),
            upstream_name: upstream_name.to_string(),
            hit_count,
            last_rdata_hash: rdata_hash,
            rdata_changes,
        };

        // Evict if at capacity
        if self.entries.len() >= self.config.max_entries {
            self.evict_one().await;
        }

        self.entries.insert(key, entry);
    }

    /// Record a cache hit (for TTL alchemy frequency tracking)
    pub async fn record_hit(&self, name: &str, qtype: &RecordType) {
        let key = CacheKey {
            name: name.to_lowercase(),
            qtype: qtype.to_u16(),
        };
        if let Some(mut entry) = self.entries.get_mut(&key) {
            entry.hit_count += 1;
        }
    }

    /// Get candidates for prefetching (entries nearing TTL expiry)
    pub async fn get_prefetch_candidates(&self, threshold_ratio: f64) -> Vec<(String, RecordType)> {
        let mut candidates = Vec::new();
        for entry in self.entries.iter() {
            let elapsed = entry.inserted_at.elapsed().as_secs() as f64;
            let ttl = entry.alchemized_ttl as f64;
            if ttl > 0.0 && (elapsed / ttl) > (1.0 - threshold_ratio) && elapsed < ttl {
                // Entry is within threshold of expiry and still valid
                candidates.push((
                    entry.key().name.clone(),
                    RecordType::from(entry.key().qtype),
                ));
            }
        }
        candidates
    }

    /// Evict least-recently-hit entry
    async fn evict_one(&self) {
        let mut oldest_key = None;
        let mut lowest_score = f64::MAX;

        for entry in self.entries.iter() {
            // Score = hits / age_seconds (higher = more valuable)
            let age = entry.inserted_at.elapsed().as_secs_f64().max(1.0);
            let score = entry.hit_count as f64 / age;
            if score < lowest_score {
                lowest_score = score;
                oldest_key = Some(entry.key().clone());
            }
        }

        if let Some(key) = oldest_key {
            self.entries.remove(&key);
            self.evictions.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Extract minimum TTL from response records
    fn extract_min_ttl(&self, response: &[u8]) -> Option<u32> {
        let parsed = packet::parse_packet(response).ok()?;
        let mut min_ttl = u32::MAX;
        for record in parsed.answers.iter().chain(parsed.authorities.iter()) {
            if record.rtype != RecordType::OPT && record.ttl < min_ttl {
                min_ttl = record.ttl;
            }
        }
        if min_ttl == u32::MAX { None } else { Some(min_ttl) }
    }

    /// Simple hash of rdata for change detection
    fn hash_rdata(&self, response: &[u8]) -> u64 {
        use std::hash::{Hash, Hasher};
        use std::collections::hash_map::DefaultHasher;
        let mut hasher = DefaultHasher::new();
        // Hash just the answer section for stability
        if let Ok(parsed) = packet::parse_packet(response) {
            for record in &parsed.answers {
                record.rdata.hash(&mut hasher);
            }
        }
        hasher.finish()
    }

    /// Get cache stats for Web UI
    pub fn get_stats(&self) -> serde_json::Value {
        let total_entries = self.entries.len();
        let hits = self.hits.load(Ordering::Relaxed);
        let misses = self.misses.load(Ordering::Relaxed);
        let total = hits + misses;
        let hit_rate = if total > 0 { hits as f64 / total as f64 * 100.0 } else { 0.0 };

        serde_json::json!({
            "entries": total_entries,
            "max_entries": self.config.max_entries,
            "hits": hits,
            "misses": misses,
            "hit_rate_percent": format!("{:.1}", hit_rate),
            "evictions": self.evictions.load(Ordering::Relaxed),
            "serve_stale": self.config.serve_stale,
        })
    }

    /// List all cache entries (for Web UI / journal)
    pub fn list_entries(&self) -> Vec<serde_json::Value> {
        self.entries.iter().map(|entry| {
            let elapsed = entry.inserted_at.elapsed().as_secs() as u32;
            let remaining = if entry.alchemized_ttl > elapsed {
                entry.alchemized_ttl - elapsed
            } else {
                0
            };
            serde_json::json!({
                "name": entry.key().name,
                "type": RecordType::from(entry.key().qtype).name(),
                "original_ttl": entry.original_ttl,
                "alchemized_ttl": entry.alchemized_ttl,
                "remaining_ttl": remaining,
                "upstream": entry.upstream_name,
                "hits": entry.hit_count,
                "rdata_changes": entry.rdata_changes,
            })
        }).collect()
    }
}
