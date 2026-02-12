use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use parking_lot::RwLock;
use rand::seq::SliceRandom;
use tokio::net::UdpSocket;
use tracing::{debug, info, warn, trace};

use crate::config::RecursiveConfig;
use crate::dns::packet::{self, DnsPacket, DnsRecord};
use crate::dns::types::{RecordType, ResponseCode, DnsClass};
use crate::curiosity::CuriosityCache;
use crate::journey::JourneyTracker;

/// ルートヒントから読み込んだルートサーバー情報
#[derive(Debug, Clone)]
pub struct RootServer {
    pub name: String,
    pub ipv4: Option<Ipv4Addr>,
}

/// パラレルDFS探索の1ステップの結果
#[derive(Debug, Clone)]
struct DfsNode {
    /// このNSサーバーの名前
    ns_name: String,
    /// このNSサーバーのIP
    ns_addr: SocketAddr,
    /// ここに到達するまでの深さ
    depth: u32,
    /// このパスのスコア (低い方が良い = レイテンシベース)
    score: f64,
    /// 解決中のゾーン名
    zone: String,
}

/// 再帰解決エンジン
pub struct RecursiveResolver {
    root_servers: Vec<RootServer>,
    config: RecursiveConfig,
    /// NS名→IPのグルーキャッシュ (好奇心キャッシュと連携)
    glue_cache: Arc<RwLock<HashMap<String, Vec<IpAddr>>>>,
    /// パスごとの累積レイテンシ記録
    path_scores: Arc<RwLock<HashMap<String, f64>>>,
}

impl RecursiveResolver {
    pub fn new(config: &RecursiveConfig) -> anyhow::Result<Self> {
        let root_servers = Self::load_root_hints(&config.root_hints_path)?;
        info!(
            "🌲 Recursive resolver initialized with {} root servers from {}",
            root_servers.len(),
            config.root_hints_path
        );

        Ok(Self {
            root_servers,
            config: config.clone(),
            glue_cache: Arc::new(RwLock::new(HashMap::new())),
            path_scores: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// root.hints ファイルを読み込み
    fn load_root_hints(path: &str) -> anyhow::Result<Vec<RootServer>> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("Failed to read root hints '{}': {}", path, e))?;

        let mut servers: HashMap<String, RootServer> = HashMap::new();

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with(';') {
                continue;
            }

            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 4 {
                continue;
            }

            // NS レコード: "." → NS name
            if parts[2].eq_ignore_ascii_case("NS") {
                let ns_name = parts[3].trim_end_matches('.').to_lowercase();
                servers.entry(ns_name.clone()).or_insert(RootServer {
                    name: ns_name,
                    ipv4: None,
                });
            }

            // A レコード: ns_name → IPv4
            if parts[2].eq_ignore_ascii_case("A") {
                let ns_name = parts[0].trim_end_matches('.').to_lowercase();
                if let Ok(ip) = parts[3].parse::<Ipv4Addr>() {
                    if let Some(srv) = servers.get_mut(&ns_name) {
                        srv.ipv4 = Some(ip);
                    }
                }
            }
        }

        let result: Vec<RootServer> = servers
            .into_values()
            .filter(|s| s.ipv4.is_some())
            .collect();

        if result.is_empty() {
            return Err(anyhow::anyhow!("No valid root servers found in hints file"));
        }

        Ok(result)
    }

    /// メイン再帰解決エントリポイント - パラレルDFS探索
    pub async fn resolve(
        &self,
        qname: &str,
        qtype: RecordType,
        curiosity: &CuriosityCache,
        journey: &JourneyTracker,
    ) -> anyhow::Result<Vec<u8>> {
        let start = Instant::now();
        let query_id: u16 = {
            use rand::rngs::OsRng;
            use rand::Rng;
            OsRng.gen()
        };

        info!("🌲 Recursive resolve: {} {} (DFS mode)", qname, qtype.name());

        // ジャーニー開始
        journey.start(qname);

        // ルートサーバーからスタート
        let mut current_servers: Vec<SocketAddr> = self
            .root_servers
            .iter()
            .filter_map(|s| s.ipv4.map(|ip| SocketAddr::new(IpAddr::V4(ip), 53)))
            .collect();

        // ルートサーバーをシャッフル (負荷分散, CSPRNG)
        {
            use rand::rngs::OsRng;
            current_servers.shuffle(&mut OsRng);
        }

        journey.add_step(qname, ".", "ROOT", &format!("{} root servers", current_servers.len()));

        let mut zone = String::from(".");
        let mut depth = 0u32;
        let max_depth = self.config.max_depth;
        let mut final_response: Option<Vec<u8>> = None;

        // 反復解決ループ（DFS的に複数パスを同時探索）
        loop {
            if depth >= max_depth {
                warn!("🌲 Max recursion depth {} reached for {}", max_depth, qname);
                journey.add_step(qname, &zone, "MAX_DEPTH", "再帰深度上限到達");
                break;
            }

            // パラレルDFS: 最大 parallel_branches 個のNSに同時クエリ
            let branches = std::cmp::min(
                current_servers.len(),
                self.config.parallel_branches as usize,
            );
            let servers_to_try: Vec<SocketAddr> = current_servers[..branches].to_vec();

            debug!(
                "🌲 Depth {}: querying {} servers for {} {} (zone: {})",
                depth,
                servers_to_try.len(),
                qname,
                qtype.name(),
                zone
            );

            // 全ブランチを同時に探索
            let results = self
                .parallel_dfs_query(qname, qtype, &servers_to_try, depth)
                .await;

            // 結果をスコアでソートして最良のものを選択
            let mut best_result: Option<(DfsResult, f64)> = None;

            for (result, latency) in results {
                let score = self.calculate_path_score(&result, latency, depth);

                match &result {
                    DfsResult::Answer(response) => {
                        journey.add_step(
                            qname,
                            &result.source_desc(),
                            "ANSWER",
                            &format!("✅ 回答取得 (score: {:.2}, {:.1}ms)", score, latency.as_millis()),
                        );

                        match &best_result {
                            Some((_, best_score)) if score >= *best_score => {}
                            _ => {
                                best_result = Some((result, score));
                            }
                        }
                    }
                    DfsResult::Referral {
                        ns_names,
                        ns_addrs,
                        zone: new_zone,
                        glue_records,
                    } => {
                        journey.add_step(
                            qname,
                            &new_zone,
                            "REFERRAL",
                            &format!(
                                "→ {} ({} NS, {:.1}ms)",
                                new_zone,
                                ns_names.len(),
                                latency.as_millis()
                            ),
                        );

                        // 好奇心キャッシュ: glue レコードを保存
                        for (name, ips) in glue_records {
                            curiosity.store_glue(name, ips);
                            trace!("🐱 Curiosity: cached glue for {}", name);
                        }

                        // このReferral結果が最良ならベストに設定
                        if best_result.is_none() {
                            best_result = Some((result, score));
                        }
                    }
                    DfsResult::NxDomain(response) => {
                        journey.add_step(
                            qname,
                            &result.source_desc(),
                            "NXDOMAIN",
                            &format!("❌ ドメイン不在 ({:.1}ms)", latency.as_millis()),
                        );
                        // NXDOMAINを最終回答として返す
                        if best_result.is_none() {
                            best_result = Some((result, score));
                        }
                    }
                    DfsResult::Error(msg) => {
                        debug!("🌲 DFS branch error: {}", msg);
                    }
                }
            }

            match best_result {
                Some((DfsResult::Answer(response), _)) => {
                    final_response = Some(response);
                    break;
                }
                Some((DfsResult::NxDomain(response), _)) => {
                    final_response = Some(response);
                    break;
                }
                Some((
                    DfsResult::Referral {
                        ns_names,
                        ns_addrs,
                        zone: new_zone,
                        glue_records,
                    },
                    _,
                )) => {
                    zone = new_zone;

                    // NSのIPアドレスを解決
                    let mut next_servers = ns_addrs.clone();

                    // glueが足りないNSはglueキャッシュ or 好奇心キャッシュから探す
                    for ns_name in &ns_names {
                        if let Some(ips) = self.glue_cache.read().get(ns_name) {
                            for ip in ips {
                                if let IpAddr::V4(v4) = ip {
                                    next_servers
                                        .push(SocketAddr::new(IpAddr::V4(*v4), 53));
                                }
                            }
                        } else if let Some(ips) = curiosity.get_glue(ns_name) {
                            for ip in &ips {
                                if let IpAddr::V4(v4) = ip {
                                    next_servers
                                        .push(SocketAddr::new(IpAddr::V4(*v4), 53));
                                }
                            }
                        }
                    }

                    if next_servers.is_empty() {
                        // NSのIPが不明 → 再帰的にNS自体を解決（深さ制限あり）
                        if depth + 1 < max_depth {
                            for ns_name in ns_names.iter().take(2) {
                                debug!("🌲 Resolving NS address: {}", ns_name);
                                if let Ok(ns_response) = self
                                    .resolve_ns_address(ns_name, curiosity, journey)
                                    .await
                                {
                                    for ip in ns_response {
                                        next_servers.push(SocketAddr::new(ip, 53));
                                    }
                                }
                            }
                        }
                    }

                    if next_servers.is_empty() {
                        warn!("🌲 No NS addresses available for zone {}", zone);
                        journey.add_step(qname, &zone, "DEAD_END", "NS IP解決失敗");
                        break;
                    }

                    // シャッフルして次のラウンドへ (CSPRNG)
                    {
                        use rand::rngs::OsRng;
                        next_servers.shuffle(&mut OsRng);
                    }
                    current_servers = next_servers;
                    depth += 1;

                    // 🐱 好奇心散歩: たまに関連ドメインを先回り解決
                    if self.config.curiosity_walk && { use rand::rngs::OsRng; use rand::Rng; OsRng.gen::<f64>() } < 0.15 {
                        let walk_zone = zone.clone();
                        let curiosity_clone = curiosity.clone();
                        tokio::spawn(async move {
                            curiosity_clone.random_walk(&walk_zone).await;
                        });
                    }
                }
                _ => {
                    warn!("🌲 All DFS branches failed for {} at depth {}", qname, depth);
                    journey.add_step(qname, &zone, "ALL_FAILED", "全ブランチ失敗");
                    break;
                }
            }
        }

        let elapsed = start.elapsed();
        journey.finish(qname, elapsed);

        match final_response {
            Some(response) => {
                info!(
                    "🌲 Recursive resolve complete: {} {} in {:?} (depth: {})",
                    qname,
                    qtype.name(),
                    elapsed,
                    depth
                );
                Ok(response)
            }
            None => {
                // SERVFAIL を返す
                let query = packet::build_query(query_id, qname, qtype, false);
                packet::build_servfail(&query)
            }
        }
    }

    /// パラレルDFS: 複数のNSに同時にクエリを投げてすべての結果を収集
    async fn parallel_dfs_query(
        &self,
        qname: &str,
        qtype: RecordType,
        servers: &[SocketAddr],
        depth: u32,
    ) -> Vec<(DfsResult, Duration)> {
        let timeout = Duration::from_millis(self.config.query_timeout_ms);
        let mut tasks = Vec::new();

        for &addr in servers {
            let name = qname.to_string();
            let qt = qtype;
            let to = timeout;

            tasks.push(tokio::spawn(async move {
                let start = Instant::now();
                match Self::send_query(&name, qt, addr, to).await {
                    Ok(response) => {
                        let latency = start.elapsed();
                        let result = Self::classify_response(&response, &name);
                        (result, latency)
                    }
                    Err(e) => {
                        let latency = start.elapsed();
                        (DfsResult::Error(format!("{}: {}", addr, e)), latency)
                    }
                }
            }));
        }

        let mut results = Vec::new();
        for task in tasks {
            if let Ok(result) = task.await {
                results.push(result);
            }
        }

        // スコア順にソート (レイテンシ低い順)
        results.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));
        results
    }

    /// Send a single DNS query to an NS server (RD=0: no recursion desired).
    /// Uses CSPRNG (OsRng) for both transaction ID and source port
    /// to mitigate DNS cache poisoning (RFC 5452).
    async fn send_query(
        qname: &str,
        qtype: RecordType,
        addr: SocketAddr,
        timeout: Duration,
    ) -> anyhow::Result<Vec<u8>> {
        use rand::rngs::OsRng;
        use rand::Rng;

        // CSPRNG transaction ID (unpredictable, not based on system clock/pid)
        let query_id: u16 = OsRng.gen();
        let query = packet::build_query(query_id, qname, qtype, false); // RD=0

        // CSPRNG source port selection in ephemeral range (RFC 5452)
        let src_port: u16 = OsRng.gen_range(49152..=65535);
        let bind_addr: SocketAddr = format!("0.0.0.0:{}", src_port)
            .parse()
            .unwrap();

        let socket = match UdpSocket::bind(bind_addr).await {
            Ok(s) => s,
            Err(_) => UdpSocket::bind("0.0.0.0:0").await?,
        };

        socket.send_to(&query, addr).await?;

        let mut buf = vec![0u8; 4096];
        let len = tokio::time::timeout(timeout, socket.recv(&mut buf))
            .await
            .map_err(|_| anyhow::anyhow!("Timeout querying {}", addr))??;

        Ok(buf[..len].to_vec())
    }

    /// レスポンスを分類: Answer / Referral / NxDomain / Error
    fn classify_response(response: &[u8], qname: &str) -> DfsResult {
        let parsed = match packet::parse_packet(response) {
            Ok(p) => p,
            Err(e) => return DfsResult::Error(format!("Parse error: {}", e)),
        };

        // NXDOMAIN
        if parsed.header.rcode == ResponseCode::NxDomain {
            return DfsResult::NxDomain(response.to_vec());
        }

        // 回答あり (ANSWERセクションにレコードがある)
        if parsed.header.ancount > 0 {
            return DfsResult::Answer(response.to_vec());
        }

        // Referral (AUTHORITYセクションにNSがある)
        if parsed.header.nscount > 0 {
            let mut ns_names = Vec::new();
            let mut ns_addrs = Vec::new();
            let mut glue_records: Vec<(String, Vec<IpAddr>)> = Vec::new();
            let mut new_zone = String::new();

            // NSレコードを抽出
            for record in &parsed.authorities {
                if record.rtype == RecordType::NS {
                    if new_zone.is_empty() {
                        new_zone = record.name.clone();
                    }
                    // NS名をrdataからパース (圧縮ポインタはfull packet上で解決)
                    if let Ok(ns_name) = packet::parse_name_at_offset(response, record.rdata_offset) {
                        ns_names.push(ns_name);
                    } else if let Ok(ns_name) = packet::parse_name_from_rdata(&record.rdata, response) {
                        ns_names.push(ns_name);
                    }
                }
            }

            // Glue レコード (ADDITIONALセクションのAレコード)
            let mut glue_map: HashMap<String, Vec<IpAddr>> = HashMap::new();
            for record in &parsed.additionals {
                if record.rtype == RecordType::A && record.rdata.len() == 4 {
                    let ip = IpAddr::V4(Ipv4Addr::new(
                        record.rdata[0],
                        record.rdata[1],
                        record.rdata[2],
                        record.rdata[3],
                    ));
                    let name = record.name.to_lowercase();

                    // NSアドレスに追加
                    if ns_names.iter().any(|n| n.to_lowercase() == name) {
                        ns_addrs.push(SocketAddr::new(ip, 53));
                    }

                    glue_map.entry(name).or_default().push(ip);
                }
            }

            for (name, ips) in glue_map {
                glue_records.push((name, ips));
            }

            if new_zone.is_empty() {
                new_zone = qname.to_string();
            }

            return DfsResult::Referral {
                ns_names,
                ns_addrs,
                zone: new_zone,
                glue_records,
            };
        }

        DfsResult::Error("Empty response (no answer, no authority)".into())
    }

    /// DFSパススコアを計算
    fn calculate_path_score(&self, result: &DfsResult, latency: Duration, depth: u32) -> f64 {
        let latency_score = 1.0 / (1.0 + latency.as_millis() as f64 / 100.0);
        let depth_penalty = 1.0 / (1.0 + depth as f64 * 0.1);

        let type_bonus = match result {
            DfsResult::Answer(_) => 2.0,  // 回答は最高スコア
            DfsResult::Referral { .. } => 1.0,
            DfsResult::NxDomain(_) => 1.5, // NXDOMAINも確定的
            DfsResult::Error(_) => 0.0,
        };

        latency_score * depth_penalty * type_bonus
    }

    /// NSサーバーのIPアドレスを解決 (再帰的)
    async fn resolve_ns_address(
        &self,
        ns_name: &str,
        curiosity: &CuriosityCache,
        journey: &JourneyTracker,
    ) -> anyhow::Result<Vec<IpAddr>> {
        debug!("🌲 Resolving NS address: {}", ns_name);

        // ルートから解決
        let mut current_servers: Vec<SocketAddr> = self
            .root_servers
            .iter()
            .filter_map(|s| s.ipv4.map(|ip| SocketAddr::new(IpAddr::V4(ip), 53)))
            .collect();

        let timeout = Duration::from_millis(self.config.query_timeout_ms);

        for depth in 0..self.config.max_depth {
            if current_servers.is_empty() {
                break;
            }

            // 最初の2つに問い合わせ
            let addr = current_servers[0];
            match Self::send_query(ns_name, RecordType::A, addr, timeout).await {
                Ok(response) => {
                    let result = Self::classify_response(&response, ns_name);
                    match result {
                        DfsResult::Answer(data) => {
                            let parsed = packet::parse_packet(&data)?;
                            let mut ips = Vec::new();
                            for answer in &parsed.answers {
                                if answer.rtype == RecordType::A && answer.rdata.len() == 4 {
                                    ips.push(IpAddr::V4(Ipv4Addr::new(
                                        answer.rdata[0],
                                        answer.rdata[1],
                                        answer.rdata[2],
                                        answer.rdata[3],
                                    )));
                                }
                            }
                            if !ips.is_empty() {
                                // グルーキャッシュに保存
                                self.glue_cache
                                    .write()
                                    .insert(ns_name.to_lowercase(), ips.clone());
                                curiosity.store_glue(ns_name, &ips);
                                return Ok(ips);
                            }
                        }
                        DfsResult::Referral {
                            ns_addrs,
                            glue_records,
                            ..
                        } => {
                            for (name, ips) in &glue_records {
                                curiosity.store_glue(name, ips);
                            }
                            if !ns_addrs.is_empty() {
                                current_servers = ns_addrs;
                                continue;
                            }
                        }
                        _ => {}
                    }
                }
                Err(_) => {
                    current_servers.remove(0);
                    continue;
                }
            }
            break;
        }

        Err(anyhow::anyhow!("Failed to resolve NS address: {}", ns_name))
    }

    /// パススコア統計を取得 (Web UI用)
    pub fn get_stats(&self) -> serde_json::Value {
        let scores = self.path_scores.read();
        let top_paths: Vec<(&String, &f64)> = scores.iter().take(10).collect();
        serde_json::json!({
            "root_servers": self.root_servers.len(),
            "glue_cache_size": self.glue_cache.read().len(),
            "parallel_branches": self.config.parallel_branches,
            "max_depth": self.config.max_depth,
            "curiosity_walk": self.config.curiosity_walk,
        })
    }
}

/// DFS探索の結果タイプ
#[derive(Debug, Clone)]
enum DfsResult {
    /// 最終回答を取得
    Answer(Vec<u8>),
    /// リファラル (次のゾーンへ委譲)
    Referral {
        ns_names: Vec<String>,
        ns_addrs: Vec<SocketAddr>,
        zone: String,
        glue_records: Vec<(String, Vec<IpAddr>)>,
    },
    /// NXDOMAIN
    NxDomain(Vec<u8>),
    /// エラー
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
