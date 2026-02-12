use std::sync::Arc;
use axum::{
    Router,
    extract::{Query, State},
    response::{Html, Json},
    routing::get,
};
use serde::Deserialize;
use tracing::info;

use crate::config::Config;
use crate::dns::engine::QueryEngine;

/// Web UI server - DNS ウェザーマップ
/// リアルタイムにクエリフロー、キャッシュヒット率、upstreamレイテンシを表示
pub struct WebServer {
    engine: Arc<QueryEngine>,
    config: Arc<Config>,
}

#[derive(Clone)]
struct AppState {
    engine: Arc<QueryEngine>,
}

#[derive(Deserialize)]
struct JournalQuery {
    domain: Option<String>,
    qtype: Option<String>,
    limit: Option<usize>,
}

impl WebServer {
    pub fn new(engine: Arc<QueryEngine>, config: Arc<Config>) -> Self {
        Self { engine, config }
    }

    pub async fn run(&self) -> anyhow::Result<()> {
        if !self.config.web.enabled {
            info!("Web UI disabled");
            return Ok(());
        }

        let state = AppState {
            engine: self.engine.clone(),
        };

        let app = Router::new()
            .route("/", get(dashboard))
            .route("/api/stats", get(api_stats))
            .route("/api/cache", get(api_cache))
            .route("/api/journal", get(api_journal))
            .route("/api/upstreams", get(api_upstreams))
            .route("/api/journey", get(api_journey))
            .with_state(state);

        let addr = format!("{}:{}", self.config.web.address, self.config.web.port);
        info!("🌐 Web UI listening on http://{}", addr);

        let listener = tokio::net::TcpListener::bind(&addr).await?;
        axum::serve(listener, app).await?;
        Ok(())
    }
}

/// Dashboard HTML - embedded single-page app
async fn dashboard() -> Html<String> {
    Html(include_str!("../../static/dashboard.html").to_string())
}

/// Stats API
async fn api_stats(State(state): State<AppState>) -> Json<serde_json::Value> {
    Json(state.engine.get_stats())
}

/// Cache entries API
async fn api_cache(State(state): State<AppState>) -> Json<serde_json::Value> {
    let entries = state.engine.cache.list_entries();
    Json(serde_json::json!({
        "entries": entries,
        "stats": state.engine.cache.get_stats(),
    }))
}

/// Journal API with search
async fn api_journal(
    State(state): State<AppState>,
    Query(params): Query<JournalQuery>,
) -> Json<serde_json::Value> {
    let limit = params.limit.unwrap_or(100);
    let entries = state.engine.journal.search(
        params.domain.as_deref(),
        params.qtype.as_deref(),
        limit,
    );
    Json(serde_json::json!({
        "entries": entries,
        "stats": state.engine.journal.get_stats(),
    }))
}

/// Upstreams API
async fn api_upstreams(State(state): State<AppState>) -> Json<serde_json::Value> {
    Json(state.engine.upstream.get_stats())
}

/// Journey API - 再帰解決の旅路履歴
async fn api_journey(
    State(state): State<AppState>,
    Query(params): Query<JournalQuery>,
) -> Json<serde_json::Value> {
    let limit = params.limit.unwrap_or(20);
    let history = state.engine.get_journey_history(limit);
    Json(serde_json::json!({
        "journeys": history,
        "stats": state.engine.journey.get_stats(),
        "curiosity": state.engine.curiosity.get_stats(),
    }))
}
