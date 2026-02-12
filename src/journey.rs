use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};
use parking_lot::RwLock;
use tracing::debug;

/// 🗺️ 解決の旅路 (Resolution Journey)
/// 再帰解決の全ステップを記録し、ADDITIONALセクションのTXTレコードとして返す
/// 「このドメインはどうやって解決されたか」を可視化する変な機能

#[derive(Debug, Clone)]
pub struct JourneyStep {
    pub zone: String,
    pub action: String,    // ROOT, REFERRAL, ANSWER, NXDOMAIN, etc.
    pub detail: String,
    pub timestamp_ms: u64, // 開始からの経過ミリ秒
}

#[derive(Debug, Clone)]
pub struct Journey {
    pub qname: String,
    pub steps: Vec<JourneyStep>,
    pub started_at: Instant,
    pub total_duration: Option<Duration>,
}

/// 解決ジャーニーのトラッカー
/// 複数の同時クエリを追跡できるようにqname→Journeyのマップ
pub struct JourneyTracker {
    enabled: bool,
    active_journeys: Arc<RwLock<std::collections::HashMap<String, Journey>>>,
    /// 完了したジャーニーの履歴 (Web UI用)
    history: Arc<RwLock<VecDeque<Journey>>>,
    max_history: usize,
}

impl Clone for JourneyTracker {
    fn clone(&self) -> Self {
        Self {
            enabled: self.enabled,
            active_journeys: self.active_journeys.clone(),
            history: self.history.clone(),
            max_history: self.max_history,
        }
    }
}

impl JourneyTracker {
    pub fn new(enabled: bool) -> Self {
        Self {
            enabled,
            active_journeys: Arc::new(RwLock::new(std::collections::HashMap::new())),
            history: Arc::new(RwLock::new(VecDeque::new())),
            max_history: 100,
        }
    }

    /// ジャーニー開始
    pub fn start(&self, qname: &str) {
        if !self.enabled {
            return;
        }
        let journey = Journey {
            qname: qname.to_string(),
            steps: Vec::new(),
            started_at: Instant::now(),
            total_duration: None,
        };
        self.active_journeys
            .write()
            .insert(qname.to_lowercase(), journey);
    }

    /// ステップを追加
    pub fn add_step(&self, qname: &str, zone: &str, action: &str, detail: &str) {
        if !self.enabled {
            return;
        }
        let key = qname.to_lowercase();
        if let Some(journey) = self.active_journeys.write().get_mut(&key) {
            let elapsed = journey.started_at.elapsed().as_millis() as u64;
            journey.steps.push(JourneyStep {
                zone: zone.to_string(),
                action: action.to_string(),
                detail: detail.to_string(),
                timestamp_ms: elapsed,
            });
        }
    }

    /// ジャーニー完了
    pub fn finish(&self, qname: &str, total: Duration) {
        if !self.enabled {
            return;
        }
        let key = qname.to_lowercase();
        if let Some(mut journey) = self.active_journeys.write().remove(&key) {
            journey.total_duration = Some(total);
            debug!(
                "🗺️ Journey complete: {} ({} steps, {:?})",
                qname,
                journey.steps.len(),
                total
            );
            let mut history = self.history.write();
            if history.len() >= self.max_history {
                history.pop_front();
            }
            history.push_back(journey);
        }
    }

    /// 最新のジャーニーを取得 (指定ドメインのもの)
    pub fn get_latest(&self, qname: &str) -> Option<Journey> {
        let key = qname.to_lowercase();
        let history = self.history.read();
        history.iter().rev().find(|j| j.qname.to_lowercase() == key).cloned()
    }

    /// ジャーニーからADDITIONALセクション用のTXTレコードバイナリを生成
    /// "neko-dns.journey." の TXT レコード
    pub fn build_journey_txt(&self, qname: &str) -> Option<Vec<u8>> {
        if !self.enabled {
            return None;
        }

        let journey = self.get_latest(qname)?;
        if journey.steps.is_empty() {
            return None;
        }

        // ジャーニーのサマリーを作成
        let summary = self.format_journey(&journey);

        let mut record = Vec::new();

        // Name: "neko-dns.journey." encoded
        record.push(8);
        record.extend_from_slice(b"neko-dns");
        record.push(7);
        record.extend_from_slice(b"journey");
        record.push(0);

        // Type: TXT (16)
        record.extend_from_slice(&16u16.to_be_bytes());
        // Class: CH (3)
        record.extend_from_slice(&3u16.to_be_bytes());
        // TTL: 0
        record.extend_from_slice(&0u32.to_be_bytes());

        // RDATA: TXTとして格納
        let summary_bytes = summary.as_bytes();
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

    /// ジャーニーを人間可読なフォーマットに変換
    fn format_journey(&self, journey: &Journey) -> String {
        let mut parts: Vec<String> = Vec::new();

        for (i, step) in journey.steps.iter().enumerate() {
            let arrow = if i == 0 { "" } else { "->" };
            parts.push(format!(
                "{}{}[{}@{}ms]",
                arrow, step.zone, step.action, step.timestamp_ms
            ));
        }

        let total = journey
            .total_duration
            .map(|d| format!(" (total:{}ms)", d.as_millis()))
            .unwrap_or_default();

        format!("{}{}", parts.join(""), total)
    }

    /// Web UI / API 用の履歴取得
    pub fn get_history(&self, limit: usize) -> Vec<serde_json::Value> {
        let history = self.history.read();
        history
            .iter()
            .rev()
            .take(limit)
            .map(|j| {
                let steps: Vec<serde_json::Value> = j
                    .steps
                    .iter()
                    .map(|s| {
                        serde_json::json!({
                            "zone": s.zone,
                            "action": s.action,
                            "detail": s.detail,
                            "timestamp_ms": s.timestamp_ms,
                        })
                    })
                    .collect();

                serde_json::json!({
                    "qname": j.qname,
                    "steps": steps,
                    "total_ms": j.total_duration.map(|d| d.as_millis() as u64),
                    "step_count": j.steps.len(),
                })
            })
            .collect()
    }

    /// 統計情報
    pub fn get_stats(&self) -> serde_json::Value {
        let history = self.history.read();
        let avg_steps = if history.is_empty() {
            0.0
        } else {
            history.iter().map(|j| j.steps.len() as f64).sum::<f64>() / history.len() as f64
        };
        let avg_duration = if history.is_empty() {
            0.0
        } else {
            history
                .iter()
                .filter_map(|j| j.total_duration)
                .map(|d| d.as_millis() as f64)
                .sum::<f64>()
                / history.len() as f64
        };

        serde_json::json!({
            "total_journeys": history.len(),
            "active_journeys": self.active_journeys.read().len(),
            "avg_steps": format!("{:.1}", avg_steps),
            "avg_duration_ms": format!("{:.1}", avg_duration),
        })
    }
}
