mod config;
mod dns;
mod cache;
mod upstream;
mod chaos;
mod journal;
mod web;
mod ttl_alchemy;
mod prefetch;
mod trust;
mod edns;
mod negative;
mod neko_comment;
mod recursive;
mod journey;
mod curiosity;

use std::sync::Arc;
use tokio::net::UdpSocket;
use tracing::{info, error, warn};

use crate::config::Config;
use crate::dns::engine::QueryEngine;
use crate::web::server::WebServer;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "neko_dns=info".into()),
        )
        .init();

    info!("🐱 neko-dns v{} starting...", env!("CARGO_PKG_VERSION"));

    // Load config
    let config_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "neko-dns.toml".to_string());

    let config = Config::load(&config_path)?;
    info!("Config loaded from {}", config_path);

    let config = Arc::new(config);

    // Initialize query engine (contains cache, upstream, journal, etc.)
    let engine = Arc::new(QueryEngine::new(config.clone()).await?);

    // Start prefetch scheduler
    let prefetch_engine = engine.clone();
    tokio::spawn(async move {
        prefetch_engine.run_prefetch_loop().await;
    });

    // Start trust scorer
    let trust_engine = engine.clone();
    tokio::spawn(async move {
        trust_engine.run_trust_scorer().await;
    });

    // Start curiosity walk loop (recursive mode only)
    let curiosity_engine = engine.clone();
    tokio::spawn(async move {
        curiosity_engine.run_curiosity_walk_loop().await;
    });

    // Start Web UI
    let web_engine = engine.clone();
    let web_config = config.clone();
    tokio::spawn(async move {
        let web = WebServer::new(web_engine, web_config);
        if let Err(e) = web.run().await {
            error!("Web server error: {}", e);
        }
    });

    // Bind UDP socket
    let bind_addr = format!("{}:{}", config.listen.address, config.listen.port);
    let udp_socket = UdpSocket::bind(&bind_addr).await?;
    info!("🐱 neko-dns listening on {} (UDP)", bind_addr);

    // Bind TCP listener
    let tcp_listener = tokio::net::TcpListener::bind(&bind_addr).await?;
    info!("🐱 neko-dns listening on {} (TCP)", bind_addr);

    // TCP handler
    let tcp_engine = engine.clone();
    tokio::spawn(async move {
        loop {
            match tcp_listener.accept().await {
                Ok((stream, addr)) => {
                    let eng = tcp_engine.clone();
                    tokio::spawn(async move {
                        if let Err(e) = eng.handle_tcp(stream, addr).await {
                            warn!("TCP handler error from {}: {}", addr, e);
                        }
                    });
                }
                Err(e) => error!("TCP accept error: {}", e),
            }
        }
    });

    // Main UDP loop
    let udp_socket = std::sync::Arc::new(udp_socket);
    let mut buf = vec![0u8; 4096];
    loop {
        match udp_socket.recv_from(&mut buf).await {
            Ok((len, addr)) => {
                let packet = buf[..len].to_vec();
                let socket = udp_socket.clone();
                let eng = engine.clone();
                tokio::spawn(async move {
                    match eng.handle_query(&packet).await {
                        Ok(response) => {
                            if let Err(e) = socket.send_to(&response, addr).await {
                                warn!("Failed to send response to {}: {}", addr, e);
                            }
                        }
                        Err(e) => {
                            warn!("Query handling error from {}: {}", addr, e);
                            // Send SERVFAIL
                            if let Ok(servfail) = dns::packet::build_servfail(&packet) {
                                let _ = socket.send_to(&servfail, addr).await;
                            }
                        }
                    }
                });
            }
            Err(e) => error!("UDP recv error: {}", e),
        }
    }
}
