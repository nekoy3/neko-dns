use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use dashmap::DashMap;
use parking_lot::RwLock;
use rand::Rng;
use rand::rngs::OsRng;
use tracing::{debug, info, trace};

/// 🐱 好奇心キャッシュ (Curiosity Cache)
///
/// 再帰解決中に見つけたglueレコードやNS情報を日和見的にキャッシュし、
/// たまに「散歩」して関連ドメインを勝手に先回り解決する。
/// 猫が気まぐれにあちこち探索するように。
///
/// 特徴:
/// - Glueレコードの積極的キャッシュ
/// - ゾーン構造の学習 (よく出てくるTLDのNS構成を覚える)
/// - ランダム散歩: 解決中にたまに「ついでに」近くのドメインも見てみる
/// - 好奇心スコア: 探索された回数が多いゾーンほど好奇心スコアが上がる

#[derive(Debug, Clone)]
struct GlueEntry {
    ips: Vec<IpAddr>,
    inserted_at: Instant,
    hit_count: u64,
}

#[derive(Debug, Clone)]
struct ZoneKnowledge {
    ns_names: Vec<String>,
    last_seen: Instant,
    query_count: u64,
    /// 好奇心スコア: このゾーンへの興味度
    curiosity_score: f64,
}

pub struct CuriosityCache {
    /// NS名 → IPアドレスのglueキャッシュ
    glue: Arc<DashMap<String, GlueEntry>>,
    /// ゾーン名 → 学習したNS構成
    zone_knowledge: Arc<DashMap<String, ZoneKnowledge>>,
    /// 散歩候補 (先回り解決したいドメインリスト)
    walk_queue: Arc<RwLock<Vec<String>>>,
    /// 散歩で実際に解決した数
    walk_count: Arc<std::sync::atomic::AtomicU64>,
    /// 散歩で発見したキャッシュヒット数
    walk_hits: Arc<std::sync::atomic::AtomicU64>,
    /// glue TTL (秒)
    glue_ttl_secs: u64,
}

impl Clone for CuriosityCache {
    fn clone(&self) -> Self {
        Self {
            glue: self.glue.clone(),
            zone_knowledge: self.zone_knowledge.clone(),
            walk_queue: self.walk_queue.clone(),
            walk_count: self.walk_count.clone(),
            walk_hits: self.walk_hits.clone(),
            glue_ttl_secs: self.glue_ttl_secs,
        }
    }
}

impl CuriosityCache {
    pub fn new(glue_ttl_secs: u64) -> Self {
        Self {
            glue: Arc::new(DashMap::new()),
            zone_knowledge: Arc::new(DashMap::new()),
            walk_queue: Arc::new(RwLock::new(Vec::new())),
            walk_count: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            walk_hits: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            glue_ttl_secs,
        }
    }

    /// Glueレコードを保存
    pub fn store_glue(&self, ns_name: &str, ips: &[IpAddr]) {
        let key = ns_name.to_lowercase();
        self.glue.insert(
            key.clone(),
            GlueEntry {
                ips: ips.to_vec(),
                inserted_at: Instant::now(),
                hit_count: 0,
            },
        );
        trace!("🐱 Curiosity: stored glue for {} ({} IPs)", ns_name, ips.len());
    }

    /// Glueレコードを取得 (TTL内のもの)
    pub fn get_glue(&self, ns_name: &str) -> Option<Vec<IpAddr>> {
        let key = ns_name.to_lowercase();
        if let Some(mut entry) = self.glue.get_mut(&key) {
            if entry.inserted_at.elapsed().as_secs() < self.glue_ttl_secs {
                entry.hit_count += 1;
                return Some(entry.ips.clone());
            } else {
                // TTL切れ → 削除
                drop(entry);
                self.glue.remove(&key);
            }
        }
        None
    }

    /// ゾーン構成を学習
    pub fn learn_zone(&self, zone: &str, ns_names: &[String]) {
        let key = zone.to_lowercase();
        if let Some(mut existing) = self.zone_knowledge.get_mut(&key) {
            existing.query_count += 1;
            existing.last_seen = Instant::now();
            // 好奇心スコアを更新: よく見るゾーンほど上がる
            existing.curiosity_score = (existing.query_count as f64).log2().min(10.0);
        } else {
            self.zone_knowledge.insert(
                key,
                ZoneKnowledge {
                    ns_names: ns_names.to_vec(),
                    last_seen: Instant::now(),
                    query_count: 1,
                    curiosity_score: 0.0,
                },
            );
        }
    }

    /// 🐱 ランダム散歩 - 探索中のゾーンの近くを勝手に見に行く
    /// 猫が気まぐれに隣の部屋を覗くような感じ
    pub async fn random_walk(&self, current_zone: &str) {
        // よくあるサブドメインプレフィックスで散歩
        let prefixes = ["www", "mail", "ns1", "ns2", "mx", "api"];

        let prefix = prefixes[OsRng.gen_range(0..prefixes.len())];
        let walk_target = format!("{}.{}", prefix, current_zone);

        debug!("🐱 Curiosity walk: wandering to {}", walk_target);
        self.walk_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        // 散歩キューに追加 (実際の解決はメインエンジンが行う)
        let mut queue = self.walk_queue.write();
        if queue.len() < 50 {
            // キューが溢れないように
            queue.push(walk_target);
        }
    }

    /// 散歩キューからドメインを1つ取得
    pub fn pop_walk_target(&self) -> Option<String> {
        let mut queue = self.walk_queue.write();
        queue.pop()
    }

    /// 期限切れエントリのクリーンアップ
    pub fn cleanup(&self) {
        let ttl = self.glue_ttl_secs;
        self.glue.retain(|_, entry| entry.inserted_at.elapsed().as_secs() < ttl);

        // 1時間以上見てないゾーンを忘れる
        self.zone_knowledge
            .retain(|_, zk| zk.last_seen.elapsed().as_secs() < 3600);
    }

    /// 好奇心スコアが高いゾーンTop Nを取得
    pub fn top_curious_zones(&self, n: usize) -> Vec<(String, f64)> {
        let mut zones: Vec<(String, f64)> = self
            .zone_knowledge
            .iter()
            .map(|entry| (entry.key().clone(), entry.curiosity_score))
            .collect();
        zones.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        zones.truncate(n);
        zones
    }

    /// 統計情報 (Web UI用)
    pub fn get_stats(&self) -> serde_json::Value {
        let top_zones = self.top_curious_zones(5);
        let top_zones_json: Vec<serde_json::Value> = top_zones
            .iter()
            .map(|(z, s)| serde_json::json!({"zone": z, "curiosity_score": format!("{:.1}", s)}))
            .collect();

        let total_glue_hits: u64 = self.glue.iter().map(|e| e.hit_count).sum();

        serde_json::json!({
            "glue_entries": self.glue.len(),
            "zone_knowledge": self.zone_knowledge.len(),
            "total_glue_hits": total_glue_hits,
            "walk_count": self.walk_count.load(std::sync::atomic::Ordering::Relaxed),
            "walk_hits": self.walk_hits.load(std::sync::atomic::Ordering::Relaxed),
            "walk_queue_size": self.walk_queue.read().len(),
            "top_curious_zones": top_zones_json,
        })
    }
}
