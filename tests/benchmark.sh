#!/bin/bash
# ============================================================
# 🐱 neko-dns vs unbound ベンチマーク比較
# Usage: ./benchmark.sh [neko-dns-ip] [unbound-ip]
# ============================================================

NEKO_DNS="${1:-127.0.0.1}"
UNBOUND="${2:-127.0.0.53}"
ROUNDS=100

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# テスト用ドメインリスト
DOMAINS=(
    "google.com"
    "github.com"
    "amazon.co.jp"
    "cloudflare.com"
    "twitter.com"
    "youtube.com"
    "reddit.com"
    "stackoverflow.com"
    "wikipedia.org"
    "netflix.com"
    "apple.com"
    "microsoft.com"
    "facebook.com"
    "yahoo.co.jp"
    "rakuten.co.jp"
    "example.com"
    "mozilla.org"
    "nginx.org"
    "rust-lang.org"
    "archlinux.org"
)

echo -e "${CYAN}"
echo "  ╔══════════════════════════════════════════════════════╗"
echo "  ║     🐱 neko-dns vs 🔒 unbound  ベンチマーク        ║"
echo "  ╠══════════════════════════════════════════════════════╣"
echo -e "  ║  neko-dns : ${NEKO_DNS}                        ║"
echo -e "  ║  unbound  : ${UNBOUND}                         ║"
echo -e "  ║  Rounds   : ${ROUNDS} queries / test               ║"
echo "  ╚══════════════════════════════════════════════════════╝"
echo -e "${NC}"

# ============================================================
# ユーティリティ関数
# ============================================================

measure_single() {
    local server="$1"
    local domain="$2"
    local start_ns=$(date +%s%N 2>/dev/null || python3 -c "import time; print(int(time.time()*1e9))")
    dig @${server} ${domain} A +short +timeout=3 +tries=1 > /dev/null 2>&1
    local end_ns=$(date +%s%N 2>/dev/null || python3 -c "import time; print(int(time.time()*1e9))")
    echo $(( (end_ns - start_ns) / 1000000 ))
}

calc_stats() {
    local -a values=("$@")
    python3 -c "
import sys
vals = [int(x) for x in sys.argv[1:]]
vals.sort()
n = len(vals)
avg = sum(vals) / n
mn = vals[0]
mx = vals[-1]
p50 = vals[n//2]
p95 = vals[int(n*0.95)]
p99 = vals[int(n*0.99)]
print(f'{avg:.1f},{mn},{mx},{p50},{p95},{p99}')
" "${values[@]}"
}

print_bar() {
    local value=$1
    local max=$2
    local width=30
    local filled=$(python3 -c "print(int(${value}/${max}*${width}))" 2>/dev/null)
    [ -z "$filled" ] && filled=1
    [ "$filled" -lt 1 ] && filled=1
    local bar=""
    for ((i=0; i<filled; i++)); do bar+="█"; done
    for ((i=filled; i<width; i++)); do bar+="░"; done
    echo "$bar"
}

# ============================================================
# テスト1: コールドスタート（キャッシュなし）レイテンシ
# ============================================================

echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BOLD}  📊 Test 1: コールドクエリ（初回・キャッシュミス）${NC}"
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# ランダムサブドメインで強制キャッシュミス
NEKO_COLD=()
UNBOUND_COLD=()
TS=$(date +%s)

echo -n "  Testing cold queries (20 unique domains)..."
for i in $(seq 1 20); do
    domain="bench-cold-${TS}-${i}.google.com"
    ms=$(measure_single "$NEKO_DNS" "$domain")
    NEKO_COLD+=($ms)

    domain="bench-cold-${TS}-${i}-u.google.com"  
    ms=$(measure_single "$UNBOUND" "$domain")
    UNBOUND_COLD+=($ms)
done
echo " done"

NEKO_COLD_STATS=$(calc_stats "${NEKO_COLD[@]}")
UNBOUND_COLD_STATS=$(calc_stats "${UNBOUND_COLD[@]}")

IFS=',' read neko_avg neko_min neko_max neko_p50 neko_p95 neko_p99 <<< "$NEKO_COLD_STATS"
IFS=',' read ub_avg ub_min ub_max ub_p50 ub_p95 ub_p99 <<< "$UNBOUND_COLD_STATS"

max_avg=$(python3 -c "print(max(${neko_avg}, ${ub_avg}))")

echo ""
echo -e "  ${GREEN}🐱 neko-dns${NC}"
echo -e "    avg: ${BOLD}${neko_avg}ms${NC}  min: ${neko_min}ms  max: ${neko_max}ms  p50: ${neko_p50}ms  p95: ${neko_p95}ms"
echo -e "    $(print_bar ${neko_avg%.*} ${max_avg%.*}) ${neko_avg}ms"
echo ""
echo -e "  ${CYAN}🔒 unbound${NC}"
echo -e "    avg: ${BOLD}${ub_avg}ms${NC}  min: ${ub_min}ms  max: ${ub_max}ms  p50: ${ub_p50}ms  p95: ${ub_p95}ms"
echo -e "    $(print_bar ${ub_avg%.*} ${max_avg%.*}) ${ub_avg}ms"
echo ""

# ============================================================
# テスト2: ウォームキャッシュ（キャッシュヒット）レイテンシ
# ============================================================

echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BOLD}  📊 Test 2: ウォームクエリ（キャッシュヒット）${NC}"
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# まずキャッシュを温める
echo -n "  Warming up caches..."
for domain in "${DOMAINS[@]}"; do
    dig @${NEKO_DNS} ${domain} A +short +timeout=3 > /dev/null 2>&1 &
    dig @${UNBOUND} ${domain} A +short +timeout=3 > /dev/null 2>&1 &
done
wait
sleep 1
echo " done"

# キャッシュヒットを計測
NEKO_WARM=()
UNBOUND_WARM=()
DOMAIN_COUNT=${#DOMAINS[@]}

echo -n "  Testing cached queries (${ROUNDS} rounds)..."
for i in $(seq 1 ${ROUNDS}); do
    idx=$(( (i - 1) % DOMAIN_COUNT ))
    domain="${DOMAINS[$idx]}"
    
    ms=$(measure_single "$NEKO_DNS" "$domain")
    NEKO_WARM+=($ms)
    
    ms=$(measure_single "$UNBOUND" "$domain")
    UNBOUND_WARM+=($ms)
    
    if (( i % 25 == 0 )); then
        echo -n "."
    fi
done
echo " done"

NEKO_WARM_STATS=$(calc_stats "${NEKO_WARM[@]}")
UNBOUND_WARM_STATS=$(calc_stats "${UNBOUND_WARM[@]}")

IFS=',' read neko_avg neko_min neko_max neko_p50 neko_p95 neko_p99 <<< "$NEKO_WARM_STATS"
IFS=',' read ub_avg ub_min ub_max ub_p50 ub_p95 ub_p99 <<< "$UNBOUND_WARM_STATS"

max_avg=$(python3 -c "print(max(${neko_avg}, ${ub_avg}))")

echo ""
echo -e "  ${GREEN}🐱 neko-dns${NC}"
echo -e "    avg: ${BOLD}${neko_avg}ms${NC}  min: ${neko_min}ms  max: ${neko_max}ms  p50: ${neko_p50}ms  p95: ${neko_p95}ms  p99: ${neko_p99}ms"
echo -e "    $(print_bar ${neko_avg%.*} ${max_avg%.*}) ${neko_avg}ms"
echo ""
echo -e "  ${CYAN}🔒 unbound${NC}"
echo -e "    avg: ${BOLD}${ub_avg}ms${NC}  min: ${ub_min}ms  max: ${ub_max}ms  p50: ${ub_p50}ms  p95: ${ub_p95}ms  p99: ${ub_p99}ms"
echo -e "    $(print_bar ${ub_avg%.*} ${max_avg%.*}) ${ub_avg}ms"
echo ""

# 勝者判定
winner_warm=$(python3 -c "print('neko-dns 🐱' if ${neko_avg} < ${ub_avg} else 'unbound 🔒')")
diff_warm=$(python3 -c "
n=${neko_avg}; u=${ub_avg}
if n < u:
    print(f'{((u-n)/u)*100:.1f}% faster')
else:
    print(f'{((n-u)/n)*100:.1f}% slower')
")

echo -e "  ${BOLD}⚡ Winner: ${winner_warm} (${diff_warm})${NC}"
echo ""

# ============================================================
# テスト3: スループット（並列クエリ）
# ============================================================

echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BOLD}  📊 Test 3: スループット（50並列クエリ）${NC}"
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

PARALLEL=50

echo -n "  neko-dns: "
start_ns=$(date +%s%N)
for i in $(seq 1 ${PARALLEL}); do
    idx=$(( (i - 1) % DOMAIN_COUNT ))
    dig @${NEKO_DNS} ${DOMAINS[$idx]} A +short +timeout=3 +tries=1 > /dev/null 2>&1 &
done
wait
end_ns=$(date +%s%N)
neko_throughput_ms=$(( (end_ns - start_ns) / 1000000 ))
neko_qps=$(python3 -c "print(f'{${PARALLEL}/(${neko_throughput_ms}/1000):.1f}')")
echo "${neko_throughput_ms}ms for ${PARALLEL} queries (${neko_qps} qps)"

echo -n "  unbound:  "
start_ns=$(date +%s%N)
for i in $(seq 1 ${PARALLEL}); do
    idx=$(( (i - 1) % DOMAIN_COUNT ))
    dig @${UNBOUND} ${DOMAINS[$idx]} A +short +timeout=3 +tries=1 > /dev/null 2>&1 &
done
wait
end_ns=$(date +%s%N)
ub_throughput_ms=$(( (end_ns - start_ns) / 1000000 ))
ub_qps=$(python3 -c "print(f'{${PARALLEL}/(${ub_throughput_ms}/1000):.1f}')")
echo "${ub_throughput_ms}ms for ${PARALLEL} queries (${ub_qps} qps)"

echo ""
max_qps=$(python3 -c "print(max(${neko_qps}, ${ub_qps}))")
echo -e "  ${GREEN}🐱 neko-dns${NC}: $(print_bar ${neko_qps%.*} ${max_qps%.*}) ${neko_qps} qps"
echo -e "  ${CYAN}🔒 unbound${NC} : $(print_bar ${ub_qps%.*} ${max_qps%.*}) ${ub_qps} qps"
echo ""

# ============================================================
# テスト4: TCP レイテンシ
# ============================================================

echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BOLD}  📊 Test 4: TCP クエリレイテンシ${NC}"
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

NEKO_TCP=()
UNBOUND_TCP=()
TCP_ROUNDS=20

echo -n "  Testing TCP queries (${TCP_ROUNDS} rounds)..."
for i in $(seq 1 ${TCP_ROUNDS}); do
    idx=$(( (i - 1) % DOMAIN_COUNT ))
    domain="${DOMAINS[$idx]}"
    
    start_ns=$(date +%s%N)
    dig @${NEKO_DNS} ${domain} A +tcp +short +timeout=3 > /dev/null 2>&1
    end_ns=$(date +%s%N)
    NEKO_TCP+=($(( (end_ns - start_ns) / 1000000 )))
    
    start_ns=$(date +%s%N)
    dig @${UNBOUND} ${domain} A +tcp +short +timeout=3 > /dev/null 2>&1
    end_ns=$(date +%s%N)
    UNBOUND_TCP+=($(( (end_ns - start_ns) / 1000000 )))
done
echo " done"

NEKO_TCP_STATS=$(calc_stats "${NEKO_TCP[@]}")
UNBOUND_TCP_STATS=$(calc_stats "${UNBOUND_TCP[@]}")

IFS=',' read neko_avg neko_min neko_max neko_p50 neko_p95 neko_p99 <<< "$NEKO_TCP_STATS"
IFS=',' read ub_avg ub_min ub_max ub_p50 ub_p95 ub_p99 <<< "$UNBOUND_TCP_STATS"

max_avg=$(python3 -c "print(max(${neko_avg}, ${ub_avg}))")

echo ""
echo -e "  ${GREEN}🐱 neko-dns${NC}: avg ${BOLD}${neko_avg}ms${NC}  min: ${neko_min}ms  max: ${neko_max}ms  p50: ${neko_p50}ms"
echo -e "    $(print_bar ${neko_avg%.*} ${max_avg%.*}) ${neko_avg}ms"
echo -e "  ${CYAN}🔒 unbound${NC} : avg ${BOLD}${ub_avg}ms${NC}  min: ${ub_min}ms  max: ${ub_max}ms  p50: ${ub_p50}ms"
echo -e "    $(print_bar ${ub_avg%.*} ${max_avg%.*}) ${ub_avg}ms"
echo ""

# ============================================================
# テスト5: 多様なレコードタイプ
# ============================================================

echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BOLD}  📊 Test 5: レコードタイプ別レイテンシ${NC}"
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

RTYPES=("A" "AAAA" "MX" "CNAME" "TXT")
RTYPE_DOMAINS=("google.com" "google.com" "gmail.com" "www.github.com" "google.com")

printf "  %-8s  %-16s  %-16s  %s\n" "Type" "🐱 neko-dns" "🔒 unbound" "Winner"
printf "  %-8s  %-16s  %-16s  %s\n" "────" "───────────" "──────────" "──────"

for i in "${!RTYPES[@]}"; do
    rtype="${RTYPES[$i]}"
    domain="${RTYPE_DOMAINS[$i]}"
    
    start_ns=$(date +%s%N)
    dig @${NEKO_DNS} ${domain} ${rtype} +short +timeout=3 > /dev/null 2>&1
    end_ns=$(date +%s%N)
    neko_ms=$(( (end_ns - start_ns) / 1000000 ))
    
    start_ns=$(date +%s%N)
    dig @${UNBOUND} ${domain} ${rtype} +short +timeout=3 > /dev/null 2>&1
    end_ns=$(date +%s%N)
    ub_ms=$(( (end_ns - start_ns) / 1000000 ))
    
    if [ "$neko_ms" -le "$ub_ms" ]; then
        winner="🐱"
    else
        winner="🔒"
    fi
    
    printf "  %-8s  %-16s  %-16s  %s\n" "$rtype" "${neko_ms}ms" "${ub_ms}ms" "$winner"
done
echo ""

# ============================================================
# テスト6: NXDOMAIN (存在しないドメイン) 応答速度
# ============================================================

echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BOLD}  📊 Test 6: NXDOMAIN 応答速度${NC}"
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

NX_ROUNDS=10
NEKO_NX=()
UNBOUND_NX=()
TS=$(date +%s)

echo -n "  Testing NXDOMAIN responses..."
for i in $(seq 1 ${NX_ROUNDS}); do
    domain="this-does-not-exist-${TS}-${i}.invalid"
    
    start_ns=$(date +%s%N)
    dig @${NEKO_DNS} ${domain} A +timeout=5 +tries=1 > /dev/null 2>&1
    end_ns=$(date +%s%N)
    NEKO_NX+=($(( (end_ns - start_ns) / 1000000 )))
    
    start_ns=$(date +%s%N)
    dig @${UNBOUND} ${domain} A +timeout=5 +tries=1 > /dev/null 2>&1
    end_ns=$(date +%s%N)
    UNBOUND_NX+=($(( (end_ns - start_ns) / 1000000 )))
done
echo " done"

NEKO_NX_STATS=$(calc_stats "${NEKO_NX[@]}")
UNBOUND_NX_STATS=$(calc_stats "${UNBOUND_NX[@]}")

IFS=',' read neko_avg _ _ neko_p50 _ _ <<< "$NEKO_NX_STATS"
IFS=',' read ub_avg _ _ ub_p50 _ _ <<< "$UNBOUND_NX_STATS"

max_avg=$(python3 -c "print(max(${neko_avg}, ${ub_avg}))")

echo ""
echo -e "  ${GREEN}🐱 neko-dns${NC}: avg ${BOLD}${neko_avg}ms${NC}  p50: ${neko_p50}ms"
echo -e "    $(print_bar ${neko_avg%.*} ${max_avg%.*}) ${neko_avg}ms"
echo -e "  ${CYAN}🔒 unbound${NC} : avg ${BOLD}${ub_avg}ms${NC}  p50: ${ub_p50}ms"
echo -e "    $(print_bar ${ub_avg%.*} ${max_avg%.*}) ${ub_avg}ms"
echo ""

# ============================================================
# 最終サマリー
# ============================================================

echo ""
echo -e "${CYAN}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║${NC}          ${BOLD}📊 最終ベンチマーク結果${NC}                     ${CYAN}║${NC}"
echo -e "${CYAN}╠══════════════════════════════════════════════════════╣${NC}"

# warm cacheの結果を最終判定に使う
IFS=',' read neko_avg _ _ _ _ _ <<< "$NEKO_WARM_STATS"
IFS=',' read ub_avg _ _ _ _ _ <<< "$UNBOUND_WARM_STATS"

echo -e "${CYAN}║${NC}                                                      ${CYAN}║${NC}"
echo -e "${CYAN}║${NC}  キャッシュヒット時 (主要指標):                       ${CYAN}║${NC}"

python3 -c "
neko = ${neko_avg}
ub = ${ub_avg}
if neko < ub:
    pct = ((ub - neko) / ub) * 100
    print(f'  🐱 neko-dns: {neko:.1f}ms')
    print(f'  🔒 unbound : {ub:.1f}ms')
    print(f'')
    print(f'  🏆 neko-dns が {pct:.1f}% 高速!')
elif ub < neko:
    pct = ((neko - ub) / neko) * 100
    print(f'  🐱 neko-dns: {neko:.1f}ms')
    print(f'  🔒 unbound : {ub:.1f}ms')
    print(f'')
    print(f'  🏆 unbound が {pct:.1f}% 高速!')
else:
    print(f'  🤝 同速: {neko:.1f}ms')
" | while IFS= read -r line; do
    printf "${CYAN}║${NC}  %-52s ${CYAN}║${NC}\n" "$line"
done

echo -e "${CYAN}║${NC}                                                      ${CYAN}║${NC}"

# neko-dnsのボーナス機能
echo -e "${CYAN}╠══════════════════════════════════════════════════════╣${NC}"
echo -e "${CYAN}║${NC}  ${BOLD}🐱 neko-dns だけの機能:${NC}                             ${CYAN}║${NC}"
echo -e "${CYAN}║${NC}    ✨ TTL錬金術（動的TTL調整）                        ${CYAN}║${NC}"
echo -e "${CYAN}║${NC}    ✨ DNS信頼スコア（自動upstream切替）                ${CYAN}║${NC}"
echo -e "${CYAN}║${NC}    ✨ カオスモード（障害注入テスト）                    ${CYAN}║${NC}"
echo -e "${CYAN}║${NC}    ✨ クエリジャーナル（全クエリ記録）                  ${CYAN}║${NC}"
echo -e "${CYAN}║${NC}    ✨ 予測プリフェッチ                                 ${CYAN}║${NC}"
echo -e "${CYAN}║${NC}    ✨ タイポ予測ネガティブキャッシュ                    ${CYAN}║${NC}"
echo -e "${CYAN}║${NC}    ✨ Web UIダッシュボード                             ${CYAN}║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  ${BOLD}neko-dns Web UI: http://${NEKO_DNS}:8053${NC}"
echo ""
