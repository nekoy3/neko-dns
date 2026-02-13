use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use dashmap::DashMap;
use parking_lot::RwLock;
use rand::seq::SliceRandom;
use tokio::net::UdpSocket;
use tokio::task::JoinSet;
use tracing::{debug, info, warn};

use crate::config::RecursiveConfig;
use crate::dns::packet::{self};
use crate::dns::types::{RecordType, ResponseCode};
use crate::curiosity::CuriosityCache;
use crate::journey::JourneyTracker;

// ============================================================
// Unbound-inspired constants (proven in production)
// ============================================================

/// Minimum retransmission timeout (ms) — Unbound: 50ms
const RTT_MIN_TIMEOUT_MS: i32 = 50;
/// Maximum retransmission timeout (ms) — Unbound: 120s
const RTT_MAX_TIMEOUT_MS: i32 = 120_000;
/// Unknown server initial RTO score (ms) — Unbound: 376ms
/// Designed to fall within RTT_BAND of fast servers so unknown servers
/// get explored naturally (376 < fast_rtt + 400)
const UNKNOWN_SERVER_NICENESS: i32 = 376;
/// RTT band width (ms) — servers within best_rtt + RTT_BAND are candidates
/// Unbound uses 400ms — balances exploitation vs exploration
const RTT_BAND_MS: i32 = 400;
/// Penalty for servers that have timed out repeatedly
const TIMEOUT_PENALTY: i32 = 10_000;
/// Max consecutive timeouts before heavy penalty
const MAX_TIMEOUT_COUNT: u32 = 3;
/// Delegation cache default TTL (seconds)
const DELEG_CACHE_TTL_SECS: u64 = 1800;
/// Socket pool size
const SOCKET_POOL_SIZE: usize = 48;

// ============================================================
// Jacobson/Karels RTT Estimator (RFC 6298, adapted for DNS)
// ============================================================
//
// The same algorithm used in TCP and Unbound's infra cache.
//
//   SRTT    ← (1 − α)·SRTT + α·R       where α = 1/8
//   RTTVAR  ← (1 − β)·RTTVAR + β·|SRTT − R|  where β = 1/4
//   RTO     = SRTT + max(G, K·RTTVAR)   where K = 4

#[derive(Debug, Clone)]
struct RttInfo {
    srtt: i32,
    rttvar: i32,
    rto: i32,
    timeout_count: u32,
}

impl RttInfo {
    fn new() -> Self {
        let rttvar = UNKNOWN_SERVER_NICENESS / 4; // 94ms
        let rto = Self::calc_rto(0, rttvar);
        Self { srtt: 0, rttvar, rto, timeout_count: 0 }
    }

    fn calc_rto(srtt: i32, rttvar: i32) -> i32 {
        (srtt + 4 * rttvar)
            .max(RTT_MIN_TIMEOUT_MS)
            .min(RTT_MAX_TIMEOUT_MS)
    }

    /// Update with a successful RTT measurement
    fn update(&mut self, ms: i32) {
        if self.srtt == 0 && self.timeout_count == 0 {
            // First measurement (RFC 6298 §2.2)
            self.srtt = ms;
            self.rttvar = ms / 2;
        } else {
            let delta = ms - self.srtt;
            self.srtt += delta / 8;
            self.rttvar += (delta.abs() - self.rttvar) / 4;
        }
        self.rto = Self::calc_rto(self.srtt, self.rttvar);
        self.timeout_count = 0;
    }

    /// Record a timeout — exponential backoff (RFC 6298 §5.5)
    fn lost(&mut self, orig_rto: i32) {
        if self.rto < orig_rto { return; }
        let doubled = (orig_rto * 2).min(RTT_MAX_TIMEOUT_MS);
        if self.rto <= doubled {
            self.rto = doubled;
        }
        self.timeout_count += 1;
    }

    /// Score for server selection (lower = better)
    fn selection_score(&self) -> i32 {
        if self.timeout_count >= MAX_TIMEOUT_COUNT {
            return TIMEOUT_PENALTY + self.rto;
        }
        if self.srtt == 0 && self.timeout_count == 0 {
            return UNKNOWN_SERVER_NICENESS; // 376ms for unknown
        }
        // Unclamped SRTT + 4×RTTVAR
        self.srtt + 4 * self.rttvar
    }
}

// ============================================================
// Delegation Cache — skip root/TLD for known zones
// ============================================================

#[derive(Debug, Clone)]
struct DelegEntry {
    ns_addrs: Vec<SocketAddr>,
    ns_names: Vec<String>,
    glue_ips: HashMap<String, Vec<IpAddr>>,
    created: Instant,
    ttl_secs: u64,
}

impl DelegEntry {
    fn is_expired(&self) -> bool {
        self.created.elapsed() > Duration::from_secs(self.ttl_secs)
    }

    fn all_addrs(&self) -> Vec<SocketAddr> {
        let mut addrs = self.ns_addrs.clone();
        for ips in self.glue_ips.values() {
            for ip in ips {
                let addr = SocketAddr::new(*ip, 53);
                if !addrs.contains(&addr) {
                    addrs.push(addr);
                }
            }
        }
        addrs
    }
}

// ============================================================
// Socket Pool — pre-bound UDP sockets to eliminate syscall overhead
// ============================================================

struct SocketPool {
    available: tokio::sync::Mutex<Vec<UdpSocket>>,
    pool_size: usize,
}

impl SocketPool {
    fn new(pool_size: usize) -> Self {
        // Lazy init — sockets allocated on first acquire, returned to pool after use
        Self {
            available: tokio::sync::Mutex::new(Vec::with_capacity(pool_size)),
            pool_size,
        }
    }

    async fn acquire_or_create(&self) -> anyhow::Result<(UdpSocket, bool)> {
        {
            let mut pool = self.available.lock().await;
            if let Some(s) = pool.pop() {
                return Ok((s, true));
            }
        }
        // Pool empty/exhausted — create with CSPRNG port (RFC 5452)
        use rand::rngs::OsRng;
        use rand::Rng;
        let src_port: u16 = OsRng.gen_range(49152..=65535);
        let bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), src_port);
        let socket = match UdpSocket::bind(bind_addr).await {
            Ok(s) => s,
            Err(_) => UdpSocket::bind("0.0.0.0:0").await?,
        };
        Ok((socket, false))
    }

    async fn release(&self, socket: UdpSocket) {
        let mut pool = self.available.lock().await;
        if pool.len() < self.pool_size {
            pool.push(socket);
        }
        // If pool is full, socket is dropped (fd closed)
    }
}

// ============================================================
// Root Server Info
// ============================================================

#[derive(Debug, Clone)]
pub struct RootServer {
    pub name: String,
    pub ipv4: Option<Ipv4Addr>,
}

// ============================================================
// Recursive Resolver — the core engine
// ============================================================

pub struct RecursiveResolver {
    root_servers: Vec<RootServer>,
    config: RecursiveConfig,
    glue_cache: Arc<RwLock<HashMap<String, Vec<IpAddr>>>>,
    /// Jacobson/Karels RTT tracking per authority server IP
    infra_cache: Arc<DashMap<IpAddr, RttInfo>>,
    /// Zone delegation cache (skip root/TLD for known zones)
    deleg_cache: Arc<DashMap<String, DelegEntry>>,
    /// Pre-allocated UDP socket pool
    socket_pool: Arc<SocketPool>,
}

impl RecursiveResolver {
    pub fn new(config: &RecursiveConfig) -> anyhow::Result<Self> {
        let root_servers = Self::load_root_hints(&config.root_hints_path)?;

        let pool = SocketPool::new(SOCKET_POOL_SIZE);

        info!(
            "🌲 Recursive resolver: {} roots, Jacobson/Karels RTT, delegation cache, lazy socket pool (max {})",
            root_servers.len(),
            SOCKET_POOL_SIZE,
        );

        let resolver = Self {
            root_servers,
            config: config.clone(),
            glue_cache: Arc::new(RwLock::new(HashMap::new())),
            infra_cache: Arc::new(DashMap::new()),
            deleg_cache: Arc::new(DashMap::new()),
            socket_pool: Arc::new(pool),
        };

        // Schedule root server RTT warm-up (runs in background)
        let infra = resolver.infra_cache.clone();
        let roots: Vec<SocketAddr> = resolver.root_servers.iter()
            .filter_map(|s| s.ipv4.map(|ip| SocketAddr::new(IpAddr::V4(ip), 53)))
            .collect();
        let sp = resolver.socket_pool.clone();
        tokio::spawn(async move {
            Self::warmup_root_rtts(infra, roots, sp).await;
        });

        Ok(resolver)
    }

    /// Probe all root servers in parallel to learn RTTs before first real query.
    /// Sends a minimal ". NS" query to each root.
    async fn warmup_root_rtts(
        infra: Arc<DashMap<IpAddr, RttInfo>>,
        roots: Vec<SocketAddr>,
        pool: Arc<SocketPool>,
    ) {
        let mut set = JoinSet::new();
        for addr in roots.iter().copied() {
            let pl = pool.clone();
            set.spawn(async move {
                let start = Instant::now();
                let probe_timeout = Duration::from_millis(1500);
                let result = Self::send_query_pooled(&pl, ".", RecordType::NS, addr, probe_timeout).await;
                let latency = start.elapsed();
                (addr, result.is_ok(), latency)
            });
        }
        let mut probed = 0u32;
        while let Some(Ok((addr, ok, latency))) = set.join_next().await {
            if ok {
                infra.entry(addr.ip()).or_insert_with(RttInfo::new).update(latency.as_millis() as i32);
                probed += 1;
            } else {
                infra.entry(addr.ip()).or_insert_with(RttInfo::new).lost(UNKNOWN_SERVER_NICENESS);
            }
        }
        info!("🌲 Root warmup: {}/{} servers probed", probed, roots.len());
    }

    fn load_root_hints(path: &str) -> anyhow::Result<Vec<RootServer>> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("Failed to read root hints '{}': {}", path, e))?;

        let mut servers: HashMap<String, RootServer> = HashMap::new();
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with(';') { continue; }
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 4 { continue; }
            if parts[2].eq_ignore_ascii_case("NS") {
                let ns_name = parts[3].trim_end_matches('.').to_lowercase();
                servers.entry(ns_name.clone()).or_insert(RootServer { name: ns_name, ipv4: None });
            }
            if parts[2].eq_ignore_ascii_case("A") {
                let ns_name = parts[0].trim_end_matches('.').to_lowercase();
                if let Ok(ip) = parts[3].parse::<Ipv4Addr>() {
                    if let Some(srv) = servers.get_mut(&ns_name) {
                        srv.ipv4 = Some(ip);
                    }
                }
            }
        }
        let result: Vec<RootServer> = servers.into_values().filter(|s| s.ipv4.is_some()).collect();
        if result.is_empty() {
            return Err(anyhow::anyhow!("No valid root servers found in hints file"));
        }
        Ok(result)
    }

    // ============================================================
    // Delegation Cache
    // ============================================================

    /// Walk labels from most-specific to root, return first cached delegation.
    /// Example: "www.example.com" → check "example.com" → "com" → root
    fn find_closest_delegation(&self, qname: &str) -> (Vec<SocketAddr>, String, u32) {
        let name = qname.trim_end_matches('.').to_lowercase();
        let labels: Vec<&str> = name.split('.').collect();

        for i in 1..labels.len() {
            let zone = labels[i..].join(".");
            if let Some(entry) = self.deleg_cache.get(&zone) {
                if !entry.is_expired() {
                    let addrs = entry.all_addrs();
                    if !addrs.is_empty() {
                        debug!("🗺️ Delegation cache HIT: {} → {} ({} servers)", qname, zone, addrs.len());
                        return (addrs, zone, i as u32);
                    }
                } else {
                    drop(entry);
                    self.deleg_cache.remove(&zone);
                }
            }
        }

        let root_addrs: Vec<SocketAddr> = self.root_servers.iter()
            .filter_map(|s| s.ipv4.map(|ip| SocketAddr::new(IpAddr::V4(ip), 53)))
            .collect();
        (root_addrs, ".".to_string(), 0)
    }

    fn store_delegation(&self, zone: &str, ns_names: &[String], ns_addrs: &[SocketAddr], glue_records: &[(String, Vec<IpAddr>)]) {
        let zone_key = zone.trim_end_matches('.').to_lowercase();
        if zone_key.is_empty() { return; }

        let mut glue_ips = HashMap::new();
        for (name, ips) in glue_records {
            glue_ips.insert(name.to_lowercase(), ips.clone());
        }

        self.deleg_cache.insert(zone_key, DelegEntry {
            ns_addrs: ns_addrs.to_vec(),
            ns_names: ns_names.to_vec(),
            glue_ips,
            created: Instant::now(),
            ttl_secs: DELEG_CACHE_TTL_SECS,
        });
    }

    // ============================================================
    // RTT-Band Server Selection (Unbound's algorithm)
    // ============================================================

    /// Select servers using RTT-band algorithm.
    /// 1. Score all servers by Jacobson/Karels RTT (lower = faster)
    /// 2. Find minimum score
    /// 3. All servers within min + RTT_BAND are candidates
    /// 4. Random select from candidates
    fn select_servers_by_rtt(&self, servers: &[SocketAddr], max_count: usize) -> Vec<SocketAddr> {
        if servers.is_empty() { return vec![]; }

        let mut scored: Vec<(SocketAddr, i32)> = servers.iter()
            .map(|&addr| {
                let score = self.infra_cache.get(&addr.ip())
                    .map(|r| r.selection_score())
                    .unwrap_or(UNKNOWN_SERVER_NICENESS);
                (addr, score)
            })
            .collect();

        scored.sort_by_key(|&(_, s)| s);

        let min_score = scored[0].1;
        // Adaptive band: narrow for known-fast, wide for unknown
        let band = if min_score < 100 { 200 } else { RTT_BAND_MS };
        let band_limit = min_score + band;

        let mut candidates: Vec<SocketAddr> = scored.iter()
            .filter(|&&(_, s)| s <= band_limit)
            .map(|&(addr, _)| addr)
            .collect();

        {
            use rand::rngs::OsRng;
            candidates.shuffle(&mut OsRng);
        }
        candidates.truncate(max_count);
        candidates
    }

    fn record_rtt(&self, addr: &SocketAddr, latency_ms: i32) {
        self.infra_cache.entry(addr.ip()).or_insert_with(RttInfo::new).update(latency_ms);
    }

    fn record_timeout(&self, addr: &SocketAddr) {
        let orig_rto = self.infra_cache.get(&addr.ip()).map(|r| r.rto).unwrap_or(UNKNOWN_SERVER_NICENESS);
        self.infra_cache.entry(addr.ip()).or_insert_with(RttInfo::new).lost(orig_rto);
    }

    // ============================================================
    // Main Resolve
    // ============================================================

    pub async fn resolve(
        &self,
        qname: &str,
        qtype: RecordType,
        curiosity: &CuriosityCache,
        journey: &JourneyTracker,
    ) -> anyhow::Result<Vec<u8>> {
        let start = Instant::now();
        let query_id: u16 = { use rand::rngs::OsRng; use rand::Rng; OsRng.gen() };

        info!("🌲 Recursive resolve: {} {} (DFS mode)", qname, qtype.name());
        journey.start(qname);

        // === Find closest cached delegation (skip root/TLD) ===
        let (initial_servers, initial_zone, levels_skipped) = self.find_closest_delegation(qname);

        // === RTT-band server selection (not random!) ===
        let mut current_servers = self.select_servers_by_rtt(&initial_servers, 6);
        if current_servers.is_empty() { current_servers = initial_servers; }

        let mut zone = initial_zone;
        let start_depth = if levels_skipped > 0 { 1 } else { 0 };

        journey.add_step(qname, &zone,
            if levels_skipped > 0 { "DELEG_CACHE" } else { "ROOT" },
            &format!("{} servers{}", current_servers.len(),
                if levels_skipped > 0 { format!(" (skipped {} levels)", levels_skipped) } else { String::new() }),
        );

        let mut depth = start_depth;
        let max_depth = self.config.max_depth;
        let mut final_response: Option<Vec<u8>> = None;

        loop {
            if depth >= max_depth {
                warn!("🌲 Max depth {} for {}", max_depth, qname);
                journey.add_step(qname, &zone, "MAX_DEPTH", "depth limit");
                break;
            }

            // Adaptive branching: fewer parallel queries for known-fast servers
            // Always use at least 2 to handle stragglers (one slow response won't block)
            let best_score = current_servers.first()
                .and_then(|s| self.infra_cache.get(&s.ip()))
                .map(|r| r.selection_score())
                .unwrap_or(UNKNOWN_SERVER_NICENESS);
            let branches = if best_score < 100 {
                // Fast known servers — 2 for redundancy
                std::cmp::min(current_servers.len(), 2)
            } else {
                // Unknown or slow — use configured branches
                std::cmp::min(current_servers.len(), self.config.parallel_branches as usize)
            };
            let servers_to_try: Vec<SocketAddr> = current_servers[..branches].to_vec();

            debug!("🌲 Depth {}: {} servers for {} (zone: {})", depth, servers_to_try.len(), qname, zone);

            let results = self.parallel_dfs_query(qname, qtype, &servers_to_try, depth).await;

            let mut best_result: Option<(DfsResult, f64)> = None;

            for (result, latency, _addr) in &results {
                let score = self.calculate_path_score(result, *latency, depth);

                match result {
                    DfsResult::Answer(_) => {
                        journey.add_step(qname, &result.source_desc(), "ANSWER",
                            &format!("answer ({:.1}ms)", latency.as_millis()));
                        match &best_result {
                            Some((_, bs)) if score >= *bs => {}
                            _ => best_result = Some((result.clone(), score)),
                        }
                    }
                    DfsResult::Referral { ns_names, zone: new_zone, glue_records, .. } => {
                        journey.add_step(qname, new_zone, "REFERRAL",
                            &format!("→ {} ({} NS, {:.1}ms)", new_zone, ns_names.len(), latency.as_millis()));
                        for (name, ips) in glue_records { curiosity.store_glue(name, ips); }
                        // Cache delegation for future queries
                        if let DfsResult::Referral { ns_names: n, ns_addrs: a, zone: z, glue_records: g } = result {
                            self.store_delegation(z, n, a, g);
                        }
                        if best_result.is_none() { best_result = Some((result.clone(), score)); }
                    }
                    DfsResult::NxDomain(_) => {
                        journey.add_step(qname, &result.source_desc(), "NXDOMAIN",
                            &format!("NXDOMAIN ({:.1}ms)", latency.as_millis()));
                        if best_result.is_none() { best_result = Some((result.clone(), score)); }
                    }
                    DfsResult::Error(msg) => { debug!("🌲 Error: {}", msg); }
                }
            }

            match best_result {
                Some((DfsResult::Answer(response), _)) => { final_response = Some(response); break; }
                Some((DfsResult::NxDomain(response), _)) => { final_response = Some(response); break; }
                Some((DfsResult::Referral { ns_names, ns_addrs, zone: new_zone, glue_records }, _)) => {
                    zone = new_zone;
                    let mut next_servers = ns_addrs.clone();

                    // Resolve missing NS IPs from caches
                    for ns_name in &ns_names {
                        let ns_lower = ns_name.to_lowercase();
                        if let Some(ips) = self.glue_cache.read().get(&ns_lower) {
                            for ip in ips {
                                let addr = SocketAddr::new(*ip, 53);
                                if !next_servers.contains(&addr) { next_servers.push(addr); }
                            }
                        } else if let Some(ips) = curiosity.get_glue(ns_name) {
                            for ip in &ips {
                                let addr = SocketAddr::new(*ip, 53);
                                if !next_servers.contains(&addr) { next_servers.push(addr); }
                            }
                        }
                    }

                    // Parallel NS resolution if needed
                    if next_servers.is_empty() && depth + 1 < max_depth {
                        let ns_to_resolve: Vec<&String> = ns_names.iter().take(3).collect();
                        match ns_to_resolve.len() {
                            3 => {
                                let (r1, r2, r3) = tokio::join!(
                                    self.resolve_ns_address(ns_to_resolve[0], curiosity, journey),
                                    self.resolve_ns_address(ns_to_resolve[1], curiosity, journey),
                                    self.resolve_ns_address(ns_to_resolve[2], curiosity, journey),
                                );
                                for r in [r1, r2, r3] {
                                    if let Ok(ips) = r { for ip in ips { next_servers.push(SocketAddr::new(ip, 53)); } }
                                }
                            }
                            2 => {
                                let (r1, r2) = tokio::join!(
                                    self.resolve_ns_address(ns_to_resolve[0], curiosity, journey),
                                    self.resolve_ns_address(ns_to_resolve[1], curiosity, journey),
                                );
                                for r in [r1, r2] {
                                    if let Ok(ips) = r { for ip in ips { next_servers.push(SocketAddr::new(ip, 53)); } }
                                }
                            }
                            1 => {
                                if let Ok(ips) = self.resolve_ns_address(ns_to_resolve[0], curiosity, journey).await {
                                    for ip in ips { next_servers.push(SocketAddr::new(ip, 53)); }
                                }
                            }
                            _ => {}
                        }
                    }

                    if next_servers.is_empty() {
                        warn!("🌲 No NS addresses for zone {}", zone);
                        journey.add_step(qname, &zone, "DEAD_END", "NS resolution failed");
                        break;
                    }

                    // RTT-band selection for next round
                    current_servers = self.select_servers_by_rtt(&next_servers, 6);
                    if current_servers.is_empty() {
                        use rand::rngs::OsRng;
                        current_servers = next_servers;
                        current_servers.shuffle(&mut OsRng);
                    }
                    depth += 1;

                    // Curiosity walk
                    if self.config.curiosity_walk && { use rand::rngs::OsRng; use rand::Rng; OsRng.gen::<f64>() } < 0.15 {
                        let wz = zone.clone();
                        let cc = curiosity.clone();
                        tokio::spawn(async move { cc.random_walk(&wz).await; });
                    }
                }
                _ => {
                    warn!("🌲 All branches failed for {} at depth {}", qname, depth);
                    journey.add_step(qname, &zone, "ALL_FAILED", "all branches failed");
                    break;
                }
            }
        }

        let elapsed = start.elapsed();
        journey.finish(qname, elapsed);

        match final_response {
            Some(response) => {
                info!("🌲 Resolved {} {} in {:?} (depth:{}, deleg:{}, infra:{})",
                    qname, qtype.name(), elapsed, depth, self.deleg_cache.len(), self.infra_cache.len());
                Ok(response)
            }
            None => {
                let query = packet::build_query(query_id, qname, qtype, false);
                packet::build_servfail(&query)
            }
        }
    }

    // ============================================================
    // Parallel DFS Query — early exit on ANY useful result
    // ============================================================
    //
    // Key optimization: exit on first Answer OR Referral, not just Answer.
    // For a 2-hop query (.com→auth), waiting for all 3 parallel responses
    // per hop means latency = max(s1,s2,s3) instead of min(s1,s2,s3).

    async fn parallel_dfs_query(
        &self,
        qname: &str,
        qtype: RecordType,
        servers: &[SocketAddr],
        depth: u32,
    ) -> Vec<(DfsResult, Duration, SocketAddr)> {
        let base_timeout_ms = self.config.query_timeout_ms;
        let adaptive_ms = ((base_timeout_ms as f64) * (1.0 - depth as f64 * 0.1)).max(200.0) as u64;

        // === Fast path: single server → skip JoinSet overhead entirely ===
        if servers.len() == 1 {
            let addr = servers[0];
            let server_rto = self.infra_cache.get(&addr.ip()).map(|r| r.rto as u64).unwrap_or(adaptive_ms);
            let timeout = Duration::from_millis(adaptive_ms.min((server_rto * 2).max(500)));
            let start = Instant::now();
            match Self::send_query_pooled(&self.socket_pool, qname, qtype, addr, timeout).await {
                Ok(response) => {
                    let latency = start.elapsed();
                    let result = Self::classify_response(&response, qname);
                    if !matches!(result, DfsResult::Error(_)) {
                        self.record_rtt(&addr, latency.as_millis() as i32);
                    }
                    return vec![(result, latency, addr)];
                }
                Err(e) => {
                    let latency = start.elapsed();
                    self.record_timeout(&addr);
                    return vec![(DfsResult::Error(format!("{}: {}", addr, e)), latency, addr)];
                }
            }
        }

        // === Multi-server path: JoinSet with early exit ===

        let infra = self.infra_cache.clone();
        let pool = self.socket_pool.clone();
        let mut set = JoinSet::new();

        for &addr in servers {
            let name = qname.to_string();
            let qt = qtype;
            let inf = infra.clone();
            let pl = pool.clone();

            // Per-server timeout: use server RTO if known, else adaptive
            let server_rto = inf.get(&addr.ip()).map(|r| r.rto as u64).unwrap_or(adaptive_ms);
            let timeout_ms = adaptive_ms.min((server_rto * 2).max(500));
            let timeout = Duration::from_millis(timeout_ms);

            set.spawn(async move {
                let start = Instant::now();
                match Self::send_query_pooled(&pl, &name, qt, addr, timeout).await {
                    Ok(response) => {
                        let latency = start.elapsed();
                        let result = Self::classify_response(&response, &name);
                        (result, latency, addr)
                    }
                    Err(e) => {
                        let latency = start.elapsed();
                        (DfsResult::Error(format!("{}: {}", addr, e)), latency, addr)
                    }
                }
            });
        }

        let mut results = Vec::new();
        while let Some(join_result) = set.join_next().await {
            if let Ok((ref result, latency, addr)) = join_result {
                let is_useful = matches!(result, DfsResult::Answer(_) | DfsResult::Referral { .. } | DfsResult::NxDomain(_));
                let is_error = matches!(result, DfsResult::Error(_));

                // Update RTT in infra cache
                if is_error {
                    self.record_timeout(&addr);
                } else {
                    self.record_rtt(&addr, latency.as_millis() as i32);
                }

                results.push(join_result.unwrap());

                // Early exit on ANY useful result (answer, referral, or nxdomain)
                if is_useful {
                    let remaining = set.len();
                    if remaining > 0 {
                        debug!("🌲 Early exit depth {} from {} ({:.1}ms), cancel {} remaining",
                            depth, addr, latency.as_millis(), remaining);
                        set.abort_all();
                    }
                    break;
                }
            }
        }

        results.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));
        results
    }

    // ============================================================
    // Query Sending (socket pool + CSPRNG)
    // ============================================================

    async fn send_query_pooled(
        pool: &SocketPool,
        qname: &str,
        qtype: RecordType,
        addr: SocketAddr,
        timeout: Duration,
    ) -> anyhow::Result<Vec<u8>> {
        use rand::rngs::OsRng;
        use rand::Rng;

        let query_id: u16 = OsRng.gen();
        let query = packet::build_query(query_id, qname, qtype, false);

        let (socket, from_pool) = pool.acquire_or_create().await?;

        let result = async {
            socket.send_to(&query, addr).await?;
            let mut buf = vec![0u8; 4096];
            // Try up to 3 reads to handle stale data from pooled sockets
            for _attempt in 0..3 {
                let len = tokio::time::timeout(timeout, socket.recv(&mut buf))
                    .await
                    .map_err(|_| anyhow::anyhow!("Timeout querying {}", addr))??;
                if len >= 2 {
                    let resp_id = u16::from_be_bytes([buf[0], buf[1]]);
                    if resp_id == query_id {
                        return Ok(buf[..len].to_vec());
                    }
                    // Stale response from previous query — try again
                }
            }
            Err(anyhow::anyhow!("No matching response from {}", addr))
        }.await;

        // Return socket to pool (even on error — socket itself is fine)
        if from_pool {
            pool.release(socket).await;
        } else if result.is_ok() {
            // New socket that worked — add to pool for future reuse
            pool.release(socket).await;
        }

        result
    }

    // ============================================================
    // Response Classification
    // ============================================================

    fn classify_response(response: &[u8], qname: &str) -> DfsResult {
        let parsed = match packet::parse_packet(response) {
            Ok(p) => p,
            Err(e) => return DfsResult::Error(format!("Parse error: {}", e)),
        };

        if parsed.header.rcode == ResponseCode::NxDomain {
            return DfsResult::NxDomain(response.to_vec());
        }

        if parsed.header.ancount > 0 {
            return DfsResult::Answer(response.to_vec());
        }

        if parsed.header.nscount > 0 {
            let mut ns_names = Vec::new();
            let mut ns_addrs = Vec::new();
            let mut glue_records: Vec<(String, Vec<IpAddr>)> = Vec::new();
            let mut new_zone = String::new();
            let mut has_soa = false;

            for record in &parsed.authorities {
                if record.rtype == RecordType::NS {
                    if new_zone.is_empty() { new_zone = record.name.clone(); }
                    if let Ok(ns_name) = packet::parse_name_at_offset(response, record.rdata_offset) {
                        ns_names.push(ns_name);
                    } else if let Ok(ns_name) = packet::parse_name_from_rdata(&record.rdata, response) {
                        ns_names.push(ns_name);
                    }
                } else if record.rtype == RecordType::SOA {
                    has_soa = true;
                }
            }

            // NODATA response: authority has SOA but no NS records
            // This means the authoritative server confirmed the name exists
            // but has no records of the requested type — return as Answer
            if ns_names.is_empty() && has_soa {
                return DfsResult::Answer(response.to_vec());
            }

            let mut glue_map: HashMap<String, Vec<IpAddr>> = HashMap::new();
            for record in &parsed.additionals {
                if record.rtype == RecordType::A && record.rdata.len() == 4 {
                    let ip = IpAddr::V4(Ipv4Addr::new(
                        record.rdata[0], record.rdata[1], record.rdata[2], record.rdata[3],
                    ));
                    let name = record.name.to_lowercase();
                    if ns_names.iter().any(|n| n.to_lowercase() == name) {
                        ns_addrs.push(SocketAddr::new(ip, 53));
                    }
                    glue_map.entry(name).or_default().push(ip);
                }
            }

            for (name, ips) in glue_map { glue_records.push((name, ips)); }
            if new_zone.is_empty() { new_zone = qname.to_string(); }

            return DfsResult::Referral { ns_names, ns_addrs, zone: new_zone, glue_records };
        }

        DfsResult::Error("Empty response".into())
    }

    fn calculate_path_score(&self, result: &DfsResult, latency: Duration, depth: u32) -> f64 {
        let latency_score = 1.0 / (1.0 + latency.as_millis() as f64 / 100.0);
        let depth_penalty = 1.0 / (1.0 + depth as f64 * 0.1);
        let type_bonus = match result {
            DfsResult::Answer(_) => 2.0,
            DfsResult::Referral { .. } => 1.0,
            DfsResult::NxDomain(_) => 1.5,
            DfsResult::Error(_) => 0.0,
        };
        latency_score * depth_penalty * type_bonus
    }

    // ============================================================
    // NS Address Resolution (with delegation cache + RTT)
    // ============================================================

    async fn resolve_ns_address(
        &self,
        ns_name: &str,
        curiosity: &CuriosityCache,
        _journey: &JourneyTracker,
    ) -> anyhow::Result<Vec<IpAddr>> {
        debug!("🌲 Resolving NS: {}", ns_name);

        // Use delegation cache to find closest zone
        let (initial_servers, _, _) = self.find_closest_delegation(ns_name);
        let mut current_servers = self.select_servers_by_rtt(&initial_servers, 4);
        if current_servers.is_empty() { current_servers = initial_servers; }

        let base_timeout = Duration::from_millis(self.config.query_timeout_ms);

        for depth in 0..self.config.max_depth {
            if current_servers.is_empty() { break; }

            let adaptive_ms = ((base_timeout.as_millis() as f64) * (1.0 - depth as f64 * 0.1)).max(300.0) as u64;
            let timeout = Duration::from_millis(adaptive_ms);

            let selected = self.select_servers_by_rtt(&current_servers, 2);
            let to_try = if selected.is_empty() {
                current_servers.iter().take(2).cloned().collect::<Vec<_>>()
            } else { selected };

            let pool = &self.socket_pool;
            let query_results = if to_try.len() >= 2 {
                let (r1, r2) = tokio::join!(
                    Self::send_query_pooled(pool, ns_name, RecordType::A, to_try[0], timeout),
                    Self::send_query_pooled(pool, ns_name, RecordType::A, to_try[1], timeout),
                );
                for (i, res) in [&r1, &r2].iter().enumerate() {
                    if res.is_ok() { self.record_rtt(&to_try[i], 20); }
                    else { self.record_timeout(&to_try[i]); }
                }
                vec![r1, r2]
            } else {
                let s = Instant::now();
                let r = Self::send_query_pooled(pool, ns_name, RecordType::A, to_try[0], timeout).await;
                let lat = s.elapsed();
                if r.is_ok() { self.record_rtt(&to_try[0], lat.as_millis() as i32); }
                else { self.record_timeout(&to_try[0]); }
                vec![r]
            };

            let mut got_referral = false;
            for qr in query_results {
                if let Ok(response) = qr {
                    let result = Self::classify_response(&response, ns_name);
                    match result {
                        DfsResult::Answer(data) => {
                            let parsed = packet::parse_packet(&data)?;
                            let mut ips = Vec::new();
                            for answer in &parsed.answers {
                                if answer.rtype == RecordType::A && answer.rdata.len() == 4 {
                                    ips.push(IpAddr::V4(Ipv4Addr::new(
                                        answer.rdata[0], answer.rdata[1], answer.rdata[2], answer.rdata[3],
                                    )));
                                }
                            }
                            if !ips.is_empty() {
                                self.glue_cache.write().insert(ns_name.to_lowercase(), ips.clone());
                                curiosity.store_glue(ns_name, &ips);
                                return Ok(ips);
                            }
                        }
                        DfsResult::Referral { ns_addrs, ns_names, zone, glue_records } => {
                            self.store_delegation(&zone, &ns_names, &ns_addrs, &glue_records);
                            for (name, ips) in &glue_records { curiosity.store_glue(name, ips); }

                            // First try using glue addresses directly
                            if !ns_addrs.is_empty() && !got_referral {
                                current_servers = self.select_servers_by_rtt(&ns_addrs, 4);
                                if current_servers.is_empty() { current_servers = ns_addrs; }
                                got_referral = true;
                            }

                            // If no glue addresses, try resolving NS names from caches
                            if !got_referral {
                                let mut resolved_addrs = Vec::new();

                                for n in &ns_names {
                                    let nl = n.to_lowercase();
                                    if let Some(ips) = self.glue_cache.read().get(&nl) {
                                        for ip in ips { resolved_addrs.push(SocketAddr::new(*ip, 53)); }
                                    } else if let Some(ips) = curiosity.get_glue(n) {
                                        for ip in &ips { resolved_addrs.push(SocketAddr::new(*ip, 53)); }
                                    }
                                }

                                // If still empty, resolve NS names by querying from root
                                // (non-recursive: query root/TLD for the NS name's A record)
                                if resolved_addrs.is_empty() && depth < self.config.max_depth.saturating_sub(2) {
                                    let ns_to_try: Vec<&String> = ns_names.iter().take(2).collect();
                                    let pool = &self.socket_pool;
                                    let ns_timeout = Duration::from_millis(self.config.query_timeout_ms);
                                    for ns in &ns_to_try {
                                        // Find closest delegation for this NS name and query it
                                        let (ns_servers, _, _) = self.find_closest_delegation(ns);
                                        let ns_selected = self.select_servers_by_rtt(&ns_servers, 3);
                                        let try_list = if ns_selected.is_empty() {
                                            ns_servers.iter().take(3).cloned().collect::<Vec<_>>()
                                        } else { ns_selected };

                                        for srv in &try_list {
                                            if let Ok(resp) = Self::send_query_pooled(pool, ns, RecordType::A, *srv, ns_timeout).await {
                                                let classified = Self::classify_response(&resp, ns);
                                                match classified {
                                                    DfsResult::Answer(data) => {
                                                        if let Ok(parsed) = packet::parse_packet(&data) {
                                                            for ans in &parsed.answers {
                                                                if ans.rtype == RecordType::A && ans.rdata.len() == 4 {
                                                                    let ip = IpAddr::V4(Ipv4Addr::new(
                                                                        ans.rdata[0], ans.rdata[1], ans.rdata[2], ans.rdata[3],
                                                                    ));
                                                                    resolved_addrs.push(SocketAddr::new(ip, 53));
                                                                    self.glue_cache.write().insert(ns.to_lowercase(), vec![ip]);
                                                                    curiosity.store_glue(ns, &[ip]);
                                                                }
                                                            }
                                                        }
                                                        if !resolved_addrs.is_empty() { break; }
                                                    }
                                                    DfsResult::Referral { ns_addrs: ref_addrs, ns_names: ref_ns, zone: ref_zone, glue_records: ref_glue } => {
                                                        self.store_delegation(&ref_zone, &ref_ns, &ref_addrs, &ref_glue);
                                                        for (gn, gips) in &ref_glue { curiosity.store_glue(gn, gips); }
                                                        // Follow one level of referral for NS resolution
                                                        let follow_servers = if !ref_addrs.is_empty() {
                                                            ref_addrs.clone()
                                                        } else {
                                                            // Try glue from the referral
                                                            let mut gs = Vec::new();
                                                            for rn in &ref_ns {
                                                                if let Some(ips) = self.glue_cache.read().get(&rn.to_lowercase()) {
                                                                    for ip in ips { gs.push(SocketAddr::new(*ip, 53)); }
                                                                } else if let Some(ips) = curiosity.get_glue(rn) {
                                                                    for ip in &ips { gs.push(SocketAddr::new(*ip, 53)); }
                                                                }
                                                            }
                                                            gs
                                                        };
                                                        for fsrv in follow_servers.iter().take(2) {
                                                            if let Ok(resp2) = Self::send_query_pooled(pool, ns, RecordType::A, *fsrv, ns_timeout).await {
                                                                if let DfsResult::Answer(data2) = Self::classify_response(&resp2, ns) {
                                                                    if let Ok(parsed2) = packet::parse_packet(&data2) {
                                                                        for ans in &parsed2.answers {
                                                                            if ans.rtype == RecordType::A && ans.rdata.len() == 4 {
                                                                                let ip = IpAddr::V4(Ipv4Addr::new(
                                                                                    ans.rdata[0], ans.rdata[1], ans.rdata[2], ans.rdata[3],
                                                                                ));
                                                                                resolved_addrs.push(SocketAddr::new(ip, 53));
                                                                                self.glue_cache.write().insert(ns.to_lowercase(), vec![ip]);
                                                                                curiosity.store_glue(ns, &[ip]);
                                                                            }
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                            if !resolved_addrs.is_empty() { break; }
                                                        }
                                                    }
                                                    _ => {}
                                                }
                                            }
                                            if !resolved_addrs.is_empty() { break; }
                                        }
                                    }
                                }

                                if !resolved_addrs.is_empty() {
                                    current_servers = self.select_servers_by_rtt(&resolved_addrs, 4);
                                    if current_servers.is_empty() { current_servers = resolved_addrs; }
                                    got_referral = true;
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
            if got_referral { continue; }
            break;
        }

        Err(anyhow::anyhow!("Failed to resolve NS: {}", ns_name))
    }

    // ============================================================
    // Stats (Web UI)
    // ============================================================

    pub fn get_stats(&self) -> serde_json::Value {
        let mut server_rtts: Vec<(String, i32, i32, u32)> = self.infra_cache.iter()
            .map(|e| (e.key().to_string(), e.value().srtt, e.value().rto, e.value().timeout_count))
            .collect();
        server_rtts.sort_by_key(|s| s.1);
        server_rtts.truncate(20);

        let top_servers: Vec<serde_json::Value> = server_rtts.iter()
            .map(|(ip, srtt, rto, to)| serde_json::json!({"ip": ip, "srtt_ms": srtt, "rto_ms": rto, "timeouts": to}))
            .collect();

        serde_json::json!({
            "root_servers": self.root_servers.len(),
            "glue_cache_size": self.glue_cache.read().len(),
            "parallel_branches": self.config.parallel_branches,
            "max_depth": self.config.max_depth,
            "curiosity_walk": self.config.curiosity_walk,
            "infra_cache_size": self.infra_cache.len(),
            "deleg_cache_size": self.deleg_cache.len(),
            "rtt_algorithm": "Jacobson/Karels (RFC 6298)",
            "server_selection": format!("RTT-band ({}ms band)", RTT_BAND_MS),
            "top_servers": top_servers,
        })
    }
}

// ============================================================
// DFS Result Type
// ============================================================

#[derive(Debug, Clone)]
enum DfsResult {
    Answer(Vec<u8>),
    Referral {
        ns_names: Vec<String>,
        ns_addrs: Vec<SocketAddr>,
        zone: String,
        glue_records: Vec<(String, Vec<IpAddr>)>,
    },
    NxDomain(Vec<u8>),
    Error(String),
}

impl DfsResult {
    fn source_desc(&self) -> String {
        match self {
            DfsResult::Answer(_) => "authoritative".into(),
            DfsResult::Referral { zone, .. } => format!("referral:{}", zone),
            DfsResult::NxDomain(_) => "nxdomain".into(),
            DfsResult::Error(msg) => format!("error:{}", msg),
        }
    }
}
