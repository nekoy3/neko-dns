/// Trust Scorer module
///
/// upstreamごとに「信頼度」をスコアリングする。
/// - 応答の一貫性
/// - レイテンシの安定性
/// - 成功率
///
/// 閾値以下のupstreamは自動で無効化される。
///
/// 主要なロジックは UpstreamManager::recalculate_trust_scores() に実装。
/// このモジュールは追加のスコアリングロジック用。

use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct TrustReport {
    pub upstream_name: String,
    pub score: f64,
    pub success_rate: f64,
    pub latency_stability: f64,
    pub is_disabled: bool,
}

/// Format a trust score as a human-readable grade
pub fn score_to_grade(score: f64) -> &'static str {
    match score {
        s if s >= 0.9 => "A+",
        s if s >= 0.8 => "A",
        s if s >= 0.7 => "B",
        s if s >= 0.6 => "C",
        s if s >= 0.5 => "D",
        _ => "F",
    }
}
