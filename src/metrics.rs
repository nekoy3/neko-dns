//! Prometheus-compatible metrics exporter for neko-dns
//!
//! Exposes metrics using naming conventions inspired by unbound_exporter
//! (https://github.com/letsencrypt/unbound_exporter) for compatibility
//! with existing Prometheus/Grafana dashboards.
//!
//! Endpoint: GET /metrics (on the web UI port, default 8053)

use std::fmt::Write;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use crate::dns::engine::QueryEngine;

/// Global metrics counters that are atomically updated from query processing
pub struct MetricsCounters {
    /// Total queries received
    pub queries_total: AtomicU64,
    /// Total cache hits
    pub cache_hits: AtomicU64,
    /// Total cache misses
    pub cache_misses: AtomicU64,
    /// Total recursive queries
    pub recursive_queries: AtomicU64,
    /// Total recursive successes
    pub recursive_successes: AtomicU64,
    /// Total recursive failures
    pub recursive_failures: AtomicU64,
    /// Total upstream forwarded queries
    pub upstream_queries: AtomicU64,
    /// Total local zone queries
    pub local_zone_queries: AtomicU64,
    /// Total negative cache hits
    pub negative_cache_hits: AtomicU64,
    /// Total prefetch operations
    pub prefetches: AtomicU64,
    /// Total stale serves
    pub stale_serves: AtomicU64,
    /// Total TCP queries
    pub tcp_queries: AtomicU64,
    /// Total SERVFAIL responses
    pub servfail_total: AtomicU64,
    /// Total NXDOMAIN responses
    pub nxdomain_total: AtomicU64,
    /// Total NOERROR responses
    pub noerror_total: AtomicU64,
    /// Query type counters
    pub query_type_a: AtomicU64,
    pub query_type_aaaa: AtomicU64,
    pub query_type_cname: AtomicU64,
    pub query_type_mx: AtomicU64,
    pub query_type_ns: AtomicU64,
    pub query_type_ptr: AtomicU64,
    pub query_type_soa: AtomicU64,
    pub query_type_srv: AtomicU64,
    pub query_type_txt: AtomicU64,
    pub query_type_any: AtomicU64,
    pub query_type_https: AtomicU64,
    pub query_type_other: AtomicU64,
    /// Server start time
    pub start_time: Instant,
    /// Recursive latency sum (in microseconds, for computing average)
    pub recursive_latency_sum_us: AtomicU64,
    /// Recursive latency count (number of samples in sum)
    pub recursive_latency_count: AtomicU64,
}

impl MetricsCounters {
    pub fn new() -> Self {
        Self {
            queries_total: AtomicU64::new(0),
            cache_hits: AtomicU64::new(0),
            cache_misses: AtomicU64::new(0),
            recursive_queries: AtomicU64::new(0),
            recursive_successes: AtomicU64::new(0),
            recursive_failures: AtomicU64::new(0),
            upstream_queries: AtomicU64::new(0),
            local_zone_queries: AtomicU64::new(0),
            negative_cache_hits: AtomicU64::new(0),
            prefetches: AtomicU64::new(0),
            stale_serves: AtomicU64::new(0),
            tcp_queries: AtomicU64::new(0),
            servfail_total: AtomicU64::new(0),
            nxdomain_total: AtomicU64::new(0),
            noerror_total: AtomicU64::new(0),
            query_type_a: AtomicU64::new(0),
            query_type_aaaa: AtomicU64::new(0),
            query_type_cname: AtomicU64::new(0),
            query_type_mx: AtomicU64::new(0),
            query_type_ns: AtomicU64::new(0),
            query_type_ptr: AtomicU64::new(0),
            query_type_soa: AtomicU64::new(0),
            query_type_srv: AtomicU64::new(0),
            query_type_txt: AtomicU64::new(0),
            query_type_any: AtomicU64::new(0),
            query_type_https: AtomicU64::new(0),
            query_type_other: AtomicU64::new(0),
            start_time: Instant::now(),
            recursive_latency_sum_us: AtomicU64::new(0),
            recursive_latency_count: AtomicU64::new(0),
        }
    }

    #[inline]
    pub fn inc_query_type(&self, qtype_name: &str) {
        match qtype_name {
            "A" => self.query_type_a.fetch_add(1, Ordering::Relaxed),
            "AAAA" => self.query_type_aaaa.fetch_add(1, Ordering::Relaxed),
            "CNAME" => self.query_type_cname.fetch_add(1, Ordering::Relaxed),
            "MX" => self.query_type_mx.fetch_add(1, Ordering::Relaxed),
            "NS" => self.query_type_ns.fetch_add(1, Ordering::Relaxed),
            "PTR" => self.query_type_ptr.fetch_add(1, Ordering::Relaxed),
            "SOA" => self.query_type_soa.fetch_add(1, Ordering::Relaxed),
            "SRV" => self.query_type_srv.fetch_add(1, Ordering::Relaxed),
            "TXT" => self.query_type_txt.fetch_add(1, Ordering::Relaxed),
            "ANY" | "*" => self.query_type_any.fetch_add(1, Ordering::Relaxed),
            "HTTPS" | "TYPE65" => self.query_type_https.fetch_add(1, Ordering::Relaxed),
            _ => self.query_type_other.fetch_add(1, Ordering::Relaxed),
        };
    }

    pub fn record_recursive_latency(&self, latency_us: u64) {
        self.recursive_latency_sum_us.fetch_add(latency_us, Ordering::Relaxed);
        self.recursive_latency_count.fetch_add(1, Ordering::Relaxed);
    }
}

/// Generate Prometheus-format metrics text
pub fn render_metrics(engine: &Arc<QueryEngine>) -> String {
    let mut out = String::with_capacity(8192);
    let c = &engine.metrics;

    // ──────────────────────────────────────────────
    // Server info (unbound-compatible)
    // ──────────────────────────────────────────────
    let uptime = c.start_time.elapsed().as_secs_f64();

    write_help_type(&mut out, "unbound_up", "Whether the DNS server is up.", "gauge");
    writeln!(out, "unbound_up 1").ok();

    write_help_type(&mut out, "unbound_time_up_seconds_total", "Uptime since server boot in seconds.", "counter");
    writeln!(out, "unbound_time_up_seconds_total {:.3}", uptime).ok();

    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64();
    write_help_type(&mut out, "unbound_time_now_seconds", "Current time in seconds since 1970.", "gauge");
    writeln!(out, "unbound_time_now_seconds {:.3}", now_secs).ok();

    // ──────────────────────────────────────────────
    // Query totals (unbound: thread0.num.queries)
    // ──────────────────────────────────────────────
    let queries_total = c.queries_total.load(Ordering::Relaxed);
    write_help_type(&mut out, "unbound_queries_total", "Total number of queries received.", "counter");
    writeln!(out, "unbound_queries_total{{thread=\"0\"}} {}", queries_total).ok();

    // ──────────────────────────────────────────────
    // Cache hits/misses (unbound: thread0.num.cachehits / cachemiss)
    // ──────────────────────────────────────────────
    let cache_hits = c.cache_hits.load(Ordering::Relaxed);
    let cache_misses = c.cache_misses.load(Ordering::Relaxed);
    write_help_type(&mut out, "unbound_cache_hits_total", "Total number of queries that were successfully answered using a cache lookup.", "counter");
    writeln!(out, "unbound_cache_hits_total{{thread=\"0\"}} {}", cache_hits).ok();

    write_help_type(&mut out, "unbound_cache_misses_total", "Total number of cache queries that needed recursive processing.", "counter");
    writeln!(out, "unbound_cache_misses_total{{thread=\"0\"}} {}", cache_misses).ok();

    // ──────────────────────────────────────────────
    // Prefetch (unbound: thread0.num.prefetch)
    // ──────────────────────────────────────────────
    let prefetches = c.prefetches.load(Ordering::Relaxed);
    write_help_type(&mut out, "unbound_prefetches_total", "Total number of cache prefetches performed.", "counter");
    writeln!(out, "unbound_prefetches_total{{thread=\"0\"}} {}", prefetches).ok();

    // ──────────────────────────────────────────────
    // Expired / stale serves (unbound: thread0.num.expired)
    // ──────────────────────────────────────────────
    let stale_serves = c.stale_serves.load(Ordering::Relaxed);
    write_help_type(&mut out, "unbound_expired_total", "Total number of expired entries served.", "counter");
    writeln!(out, "unbound_expired_total{{thread=\"0\"}} {}", stale_serves).ok();

    // ──────────────────────────────────────────────
    // Recursive replies (unbound: thread0.num.recursivereplies)
    // ──────────────────────────────────────────────
    let recursive_queries = c.recursive_queries.load(Ordering::Relaxed);
    write_help_type(&mut out, "unbound_recursive_replies_total", "Total number of replies sent to queries that needed recursive processing.", "counter");
    writeln!(out, "unbound_recursive_replies_total{{thread=\"0\"}} {}", recursive_queries).ok();

    // ──────────────────────────────────────────────
    // Recursion time avg (unbound: total.recursion.time.avg)
    // ──────────────────────────────────────────────
    let latency_count = c.recursive_latency_count.load(Ordering::Relaxed);
    let latency_sum = c.recursive_latency_sum_us.load(Ordering::Relaxed);
    let recursion_avg = if latency_count > 0 {
        (latency_sum as f64 / latency_count as f64) / 1_000_000.0 // us → seconds
    } else {
        0.0
    };
    write_help_type(&mut out, "unbound_recursion_time_seconds_avg", "Average time it took to answer queries that needed recursive processing.", "gauge");
    writeln!(out, "unbound_recursion_time_seconds_avg {:.6}", recursion_avg).ok();

    // ──────────────────────────────────────────────
    // TCP queries (unbound: num.query.tcp)
    // ──────────────────────────────────────────────
    let tcp_queries = c.tcp_queries.load(Ordering::Relaxed);
    write_help_type(&mut out, "unbound_query_tcp_total", "Total number of queries that were made using TCP.", "counter");
    writeln!(out, "unbound_query_tcp_total {}", tcp_queries).ok();

    // ──────────────────────────────────────────────
    // Answer rcodes (unbound: num.answer.rcode.*)
    // ──────────────────────────────────────────────
    let noerror = c.noerror_total.load(Ordering::Relaxed);
    let servfail = c.servfail_total.load(Ordering::Relaxed);
    let nxdomain = c.nxdomain_total.load(Ordering::Relaxed);
    write_help_type(&mut out, "unbound_answer_rcodes_total", "Total number of answers to queries, from cache or from recursion, by response code.", "counter");
    writeln!(out, "unbound_answer_rcodes_total{{rcode=\"NOERROR\"}} {}", noerror).ok();
    writeln!(out, "unbound_answer_rcodes_total{{rcode=\"SERVFAIL\"}} {}", servfail).ok();
    writeln!(out, "unbound_answer_rcodes_total{{rcode=\"NXDOMAIN\"}} {}", nxdomain).ok();

    // ──────────────────────────────────────────────
    // Query types (unbound: num.query.type.*)
    // ──────────────────────────────────────────────
    write_help_type(&mut out, "unbound_query_types_total", "Total number of queries with a given query type.", "counter");
    write_counter_if_nonzero(&mut out, "unbound_query_types_total", "type", "A", c.query_type_a.load(Ordering::Relaxed));
    write_counter_if_nonzero(&mut out, "unbound_query_types_total", "type", "AAAA", c.query_type_aaaa.load(Ordering::Relaxed));
    write_counter_if_nonzero(&mut out, "unbound_query_types_total", "type", "CNAME", c.query_type_cname.load(Ordering::Relaxed));
    write_counter_if_nonzero(&mut out, "unbound_query_types_total", "type", "MX", c.query_type_mx.load(Ordering::Relaxed));
    write_counter_if_nonzero(&mut out, "unbound_query_types_total", "type", "NS", c.query_type_ns.load(Ordering::Relaxed));
    write_counter_if_nonzero(&mut out, "unbound_query_types_total", "type", "PTR", c.query_type_ptr.load(Ordering::Relaxed));
    write_counter_if_nonzero(&mut out, "unbound_query_types_total", "type", "SOA", c.query_type_soa.load(Ordering::Relaxed));
    write_counter_if_nonzero(&mut out, "unbound_query_types_total", "type", "SRV", c.query_type_srv.load(Ordering::Relaxed));
    write_counter_if_nonzero(&mut out, "unbound_query_types_total", "type", "TXT", c.query_type_txt.load(Ordering::Relaxed));
    write_counter_if_nonzero(&mut out, "unbound_query_types_total", "type", "HTTPS", c.query_type_https.load(Ordering::Relaxed));
    write_counter_if_nonzero(&mut out, "unbound_query_types_total", "type", "ANY", c.query_type_any.load(Ordering::Relaxed));
    write_counter_if_nonzero(&mut out, "unbound_query_types_total", "type", "other", c.query_type_other.load(Ordering::Relaxed));

    // ──────────────────────────────────────────────
    // Cache size (unbound: msg.cache.count)
    // ──────────────────────────────────────────────
    let cache_stats = engine.cache.get_stats();
    let cache_entries = cache_stats["entries"].as_u64().unwrap_or(0);
    let cache_max = cache_stats["max_entries"].as_u64().unwrap_or(0);
    let cache_evictions = cache_stats["evictions"].as_u64().unwrap_or(0);

    write_help_type(&mut out, "unbound_msg_cache_count", "The number of messages cached.", "gauge");
    writeln!(out, "unbound_msg_cache_count {}", cache_entries).ok();

    write_help_type(&mut out, "unbound_msg_cache_max_size", "Maximum number of cache entries.", "gauge");
    writeln!(out, "unbound_msg_cache_max_size {}", cache_max).ok();

    // ──────────────────────────────────────────────
    // Memory (unbound: mem.cache.*)
    // Approximate: each entry ≈ 512 bytes
    // ──────────────────────────────────────────────
    let cache_mem = cache_entries * 512;
    write_help_type(&mut out, "unbound_memory_caches_bytes", "Memory in bytes in use by caches.", "gauge");
    writeln!(out, "unbound_memory_caches_bytes{{cache=\"message\"}} {}", cache_mem).ok();

    // Negative cache
    let neg_stats = engine.negative.get_stats();
    let neg_entries = neg_stats["total_entries"].as_u64().unwrap_or(0);
    let neg_mem = neg_entries * 256;
    writeln!(out, "unbound_memory_caches_bytes{{cache=\"negative\"}} {}", neg_mem).ok();

    // ──────────────────────────────────────────────
    // Negative cache hits
    // ──────────────────────────────────────────────
    let neg_hits = c.negative_cache_hits.load(Ordering::Relaxed);
    write_help_type(&mut out, "unbound_negative_cache_hits_total", "Total number of negative cache hits.", "counter");
    writeln!(out, "unbound_negative_cache_hits_total {}", neg_hits).ok();

    // ──────────────────────────────────────────────
    // Upstream stats (neko-dns specific, but useful)
    // ──────────────────────────────────────────────
    let upstream_stats = engine.upstream.get_stats();
    let upstream_queries_total = c.upstream_queries.load(Ordering::Relaxed);

    write_help_type(&mut out, "nekonsd_upstream_queries_total", "Total number of queries forwarded to upstream servers.", "counter");
    writeln!(out, "nekonsd_upstream_queries_total {}", upstream_queries_total).ok();

    write_help_type(&mut out, "nekonsd_upstream_queries", "Total queries per upstream server.", "counter");
    write_help_type(&mut out, "nekonsd_upstream_failures", "Total failures per upstream server.", "counter");
    write_help_type(&mut out, "nekonsd_upstream_avg_latency_ms", "Average latency in ms per upstream server.", "gauge");
    write_help_type(&mut out, "nekonsd_upstream_trust_score", "Trust score per upstream server (0.0-1.0).", "gauge");

    if let Some(arr) = upstream_stats.as_array() {
        for u in arr {
            let name = u["name"].as_str().unwrap_or("unknown");
            let tq = u["total_queries"].as_u64().unwrap_or(0);
            let tf = u["total_failures"].as_u64().unwrap_or(0);
            let lat = u["avg_latency_ms"].as_f64().unwrap_or(0.0);
            let trust = u["trust_score"].as_f64().unwrap_or(0.0);
            writeln!(out, "nekonsd_upstream_queries{{name=\"{}\"}} {}", name, tq).ok();
            writeln!(out, "nekonsd_upstream_failures{{name=\"{}\"}} {}", name, tf).ok();
            writeln!(out, "nekonsd_upstream_avg_latency_ms{{name=\"{}\"}} {:.1}", name, lat).ok();
            writeln!(out, "nekonsd_upstream_trust_score{{name=\"{}\"}} {:.3}", name, trust).ok();
        }
    }

    // ──────────────────────────────────────────────
    // Recursive resolver stats (unbound: infra.cache.count)
    // ──────────────────────────────────────────────
    if let Some(ref recursive) = engine.recursive {
        let rstats = recursive.get_stats();
        let infra_cache = rstats["infra_cache_size"].as_u64().unwrap_or(0);
        let deleg_cache = rstats["deleg_cache_size"].as_u64().unwrap_or(0);
        let glue_cache = rstats["glue_cache_size"].as_u64().unwrap_or(0);

        write_help_type(&mut out, "unbound_infra_cache_count", "Total number of infra cache entries.", "gauge");
        writeln!(out, "unbound_infra_cache_count {}", infra_cache).ok();

        write_help_type(&mut out, "nekonsd_deleg_cache_count", "Total number of delegation cache entries.", "gauge");
        writeln!(out, "nekonsd_deleg_cache_count {}", deleg_cache).ok();

        write_help_type(&mut out, "nekonsd_glue_cache_count", "Total number of glue cache entries.", "gauge");
        writeln!(out, "nekonsd_glue_cache_count {}", glue_cache).ok();

        let rsuc = c.recursive_successes.load(Ordering::Relaxed);
        let rfail = c.recursive_failures.load(Ordering::Relaxed);
        write_help_type(&mut out, "nekonsd_recursive_successes_total", "Total successful recursive resolutions.", "counter");
        writeln!(out, "nekonsd_recursive_successes_total {}", rsuc).ok();

        write_help_type(&mut out, "nekonsd_recursive_failures_total", "Total failed recursive resolutions.", "counter");
        writeln!(out, "nekonsd_recursive_failures_total {}", rfail).ok();
    }

    // ──────────────────────────────────────────────
    // Local zone queries (neko-dns specific)
    // ──────────────────────────────────────────────
    let local_zone = c.local_zone_queries.load(Ordering::Relaxed);
    write_help_type(&mut out, "nekonsd_local_zone_queries_total", "Total number of queries resolved via local zone forwarding.", "counter");
    writeln!(out, "nekonsd_local_zone_queries_total {}", local_zone).ok();

    // ──────────────────────────────────────────────
    // Cache evictions
    // ──────────────────────────────────────────────
    write_help_type(&mut out, "nekonsd_cache_evictions_total", "Total number of cache entries evicted.", "counter");
    writeln!(out, "nekonsd_cache_evictions_total {}", cache_evictions).ok();

    // ──────────────────────────────────────────────
    // Cache hit rate (convenience gauge)
    // ──────────────────────────────────────────────
    let total = cache_hits + cache_misses;
    let hit_rate = if total > 0 { cache_hits as f64 / total as f64 } else { 0.0 };
    write_help_type(&mut out, "nekonsd_cache_hit_ratio", "Cache hit ratio (0.0-1.0).", "gauge");
    writeln!(out, "nekonsd_cache_hit_ratio {:.4}", hit_rate).ok();

    // ──────────────────────────────────────────────
    // Journey stats (neko-dns specific)
    // ──────────────────────────────────────────────
    let journey_stats = engine.journey.get_stats();
    let total_journeys = journey_stats["total_journeys"].as_u64().unwrap_or(0);
    let avg_duration_ms = journey_stats["avg_duration_ms"].as_f64().unwrap_or(0.0);

    write_help_type(&mut out, "nekonsd_journeys_total", "Total completed resolution journeys.", "counter");
    writeln!(out, "nekonsd_journeys_total {}", total_journeys).ok();

    write_help_type(&mut out, "nekonsd_journey_avg_duration_seconds", "Average journey duration in seconds.", "gauge");
    writeln!(out, "nekonsd_journey_avg_duration_seconds {:.6}", avg_duration_ms / 1000.0).ok();

    // ──────────────────────────────────────────────
    // Curiosity cache
    // ──────────────────────────────────────────────
    let curiosity_stats = engine.curiosity.get_stats();
    let walk_count = curiosity_stats["walk_count"].as_u64().unwrap_or(0);
    let walk_hits = curiosity_stats["walk_hits"].as_u64().unwrap_or(0);

    write_help_type(&mut out, "nekonsd_curiosity_walks_total", "Total curiosity walk operations.", "counter");
    writeln!(out, "nekonsd_curiosity_walks_total {}", walk_count).ok();

    write_help_type(&mut out, "nekonsd_curiosity_walk_hits_total", "Total curiosity walk cache hits.", "counter");
    writeln!(out, "nekonsd_curiosity_walk_hits_total {}", walk_hits).ok();

    // ──────────────────────────────────────────────
    // Chaos engine
    // ──────────────────────────────────────────────
    let chaos_stats = engine.chaos.get_stats();
    let chaos_injected = chaos_stats["total_injected"].as_u64().unwrap_or(0);

    write_help_type(&mut out, "nekonsd_chaos_injections_total", "Total chaos-mode SERVFAIL injections.", "counter");
    writeln!(out, "nekonsd_chaos_injections_total {}", chaos_injected).ok();

    // ──────────────────────────────────────────────
    // Build info (like unbound_exporter_build_info)
    // ──────────────────────────────────────────────
    write_help_type(&mut out, "nekonsd_build_info", "neko-dns build information.", "gauge");
    writeln!(out, "nekonsd_build_info{{version=\"{}\"}} 1", env!("CARGO_PKG_VERSION")).ok();

    out
}

// ── helpers ─────────────────────────────────────────

fn write_help_type(out: &mut String, name: &str, help: &str, metric_type: &str) {
    writeln!(out, "# HELP {} {}", name, help).ok();
    writeln!(out, "# TYPE {} {}", name, metric_type).ok();
}

fn write_counter_if_nonzero(out: &mut String, name: &str, label: &str, value: &str, count: u64) {
    if count > 0 {
        writeln!(out, "{}{{{}=\"{}\"}} {}", name, label, value, count).ok();
    }
}
