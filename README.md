# 🐱 neko-dns

**変なキャッシュDNSサーバー** - フルスクラッチ Rust 実装

## 概要

neko-dns は RFC 1035 準拠の DNS キャッシュサーバーを基盤に、奇想天外な独自機能を盛り込んだ「性格のある」DNS サーバーです。

## 機能一覧

### コア機能

| # | 機能名 | 説明 | RFC |
|---|--------|------|-----|
| 1 | **DNS パケットパーサー** | バイナリレベルで DNS パケットを直接パース。ラベル圧縮対応。外部ライブラリ不使用 | RFC 1035 |
| 2 | **UDP/TCP リスナー** | UDP と TCP 両方でクエリを受付。TCP は長さプレフィクス対応 | RFC 1035 §4.2 |
| 3 | **キャッシュレイヤー** | DashMap ベースの高速並行キャッシュ。LFU 的な eviction | - |
| 4 | **マルチアップストリーム競争** | 全 upstream に同時クエリ→最速応答を採用 | - |
| 5 | **Serve-Stale** | TTL 切れでも一定時間はキャッシュから応答を返す | RFC 8767 |

### 変な機能

| # | 機能名 | 説明 | 確認方法 |
|---|--------|------|----------|
| 6 | **TTL 錬金術** | クエリ頻度と応答変動率から動的にTTLを再計算。よく引くドメインはTTL延長、怪しいドメインはTTL短縮 | Web UI で original_ttl vs alchemized_ttl を比較 |
| 7 | **DNS 信頼スコア** | upstream ごとに成功率・レイテンシ安定性からスコアリング。閾値以下は自動無効化 | Web UI Upstreams セクション |
| 8 | **予測プリフェッチ** | TTL 残り 10% で先回りリフレッシュ | ログで "Prefetching:" を確認 |
| 9 | **カオスモード** | 設定確率で SERVFAIL を注入。アプリのDNS障害耐性テスト | テストスクリプトで確認 |
| 10 | **クエリジャーナル** | 全クエリ/応答を時系列で記録。タイムトラベルデバッグ用 | Web UI Journal セクション & API |
| 11 | **ネガティブキャッシュ増強** | NXDOMAIN をキャッシュ + typo 亜種も推測ネガキャッシュ (speculative mode) | テストスクリプトで確認 |
| 12 | **カスタム EDNS 拡張** | EDNS0 OPT に独自オプションコードを追加可能 | dig +ednsopt でテスト |
| 13 | **DNS ウェザーマップ (Web UI)** | リアルタイムダッシュボード。キャッシュ/upstream/journal を可視化 | ブラウザでアクセス |

## アーキテクチャ

```
Client → [UDP/TCP :53] → QueryEngine
                              │
                              ├─ ChaosEngine (障害注入判定)
                              ├─ EdnsHandler (EDNS拡張処理)
                              ├─ NegativeCache (NXDOMAIN チェック)
                              ├─ CacheLayer (キャッシュ検索 / TTL錬金術)
                              │      └─ TtlAlchemy (TTL再計算)
                              ├─ UpstreamManager (マルチアップストリーム競争)
                              │      └─ TrustScorer (信頼スコア)
                              ├─ Journal (クエリ記録)
                              └─ PrefetchPredictor (先回りリフレッシュ)

Web UI → [HTTP :8053] → /api/stats, /api/cache, /api/journal, /api/upstreams
```

## 設定ファイル (neko-dns.toml)

```toml
[listen]
address = "0.0.0.0"
port = 53

[[upstreams]]
name = "google"
address = "8.8.8.8"
port = 53
timeout_ms = 2000

[cache]
max_entries = 100000
serve_stale = true

[ttl_alchemy]
enabled = true
frequency_weight = 0.3    # 頻度→TTL延長の重み
volatility_weight = 0.5   # 変動→TTL短縮の重み

[chaos]
enabled = false            # trueにすると障害注入開始
servfail_probability = 0.01

[web]
enabled = true
port = 8053
```

全設定項目は `neko-dns.toml` を参照。

## ビルド & 実行

```bash
# ビルド
cargo build --release

# 実行 (port 53 はroot権限が必要)
sudo ./target/release/neko-dns neko-dns.toml

# 開発モード (ログ詳細)
RUST_LOG=neko_dns=debug cargo run -- neko-dns.toml
```

## Web UI

`http://<server>:8053/` でダッシュボードにアクセス。

表示内容:
- 📦 **Cache**: エントリ数、ヒット率、eviction 数
- 🏎️ **Upstreams**: 各 upstream の信頼スコア、レイテンシ、クエリ数
- 🎲 **Chaos Engine**: 注入数、確率
- 🚫 **Negative Cache**: NXDOMAIN キャッシュ数
- 📜 **Query Journal**: 直近クエリのリアルタイムフロー
- 🗄️ **Cache Entries**: 全キャッシュエントリ (TTL 錬金術の効果が見える)

## 各機能の確認方法

### 1. 基本的な名前解決

```bash
dig @<server-ip> google.com A
dig @<server-ip> example.com AAAA
dig @<server-ip> -x 8.8.8.8  # PTR
```

期待結果: 正常な DNS 応答が返る。

### 2. キャッシュヒット確認

```bash
# 1回目: キャッシュミス (upstream にフォワード)
dig @<server-ip> google.com A
# 2回目: キャッシュヒット (高速応答)
dig @<server-ip> google.com A
```

期待結果: 2回目のQuery timeが大幅に短い。Web UI のヒット率が上昇。

### 3. TTL 錬金術

```bash
# 同じドメインを連続クエリ → TTL が延長される
for i in $(seq 1 20); do dig @<server-ip> google.com +short; sleep 0.5; done
```

Web UI の Cache Entries で `original_ttl` vs `alchemized_ttl` を比較。
頻繁にクエリされたドメインは alchemized_ttl > original_ttl になる。

### 4. マルチアップストリーム競争

Web UI の Upstreams セクションで各 upstream のクエリ数とレイテンシを確認。
最速の upstream が最も多くクエリに応答している。

### 5. DNS 信頼スコア

Web UI で各 upstream の Trust Score を確認。
- A+ (≥0.9): 優秀
- F (<0.5): 自動無効化

### 6. カオスモード

```bash
# neko-dns.toml で chaos.enabled = true に変更してリロード
# 大量クエリを投げて SERVFAIL の発生を確認
for i in $(seq 1 100); do dig @<server-ip> test${i}.example.com +short 2>/dev/null; done
```

一部のクエリが SERVFAIL になる。Web UI の Chaos Engine セクションで注入数を確認。

### 7. クエリジャーナル

```bash
# API で検索
curl http://<server-ip>:8053/api/journal?domain=google&limit=10
# 特定タイプのみ
curl http://<server-ip>:8053/api/journal?qtype=AAAA&limit=5
```

### 8. ネガティブキャッシュ

```bash
# 存在しないドメインをクエリ
dig @<server-ip> thisdomaindoesnotexist12345.com
# 2回目は高速 (ネガティブキャッシュヒット)
dig @<server-ip> thisdomaindoesnotexist12345.com
```

### 9. Serve-Stale (RFC 8767)

TTL 切れ後もキャッシュから応答が返る。
テスト: キャッシュに入ったドメインの TTL が切れるのを待ち、再クエリ。

### 10. TCP 対応

```bash
dig @<server-ip> google.com +tcp
```

## テストスクリプト

`tests/` ディレクトリに自動テストスクリプトあり:

```bash
# 全機能テスト
./tests/test_all.sh

# 個別テスト
./tests/test_basic.sh      # 基本名前解決
./tests/test_cache.sh       # キャッシュ動作
./tests/test_alchemy.sh     # TTL錬金術
./tests/test_chaos.sh       # カオスモード
./tests/test_journal.sh     # ジャーナル
./tests/test_negative.sh    # ネガティブキャッシュ
```

## ソースコード構成

```
src/
├── main.rs          # エントリポイント、UDP/TCP ループ
├── config.rs        # TOML 設定パーサー
├── dns/
│   ├── mod.rs
│   ├── types.rs     # RecordType, ResponseCode, DnsClass
│   ├── packet.rs    # バイナリ DNS パケットパーサー (RFC 1035)
│   └── engine.rs    # クエリエンジン (全機能の統合)
├── cache.rs         # キャッシュレイヤー (DashMap)
├── upstream.rs      # マルチアップストリーム + 競争ロジック
├── ttl_alchemy.rs   # TTL 再計算エンジン
├── prefetch.rs      # 予測プリフェッチ + 時間帯学習
├── trust.rs         # 信頼スコアリング
├── chaos.rs         # カオスエンジニアリング
├── journal.rs       # クエリジャーナル
├── edns.rs          # EDNS カスタム拡張
├── negative.rs      # ネガティブキャッシュ + typo推測
└── web/
    ├── mod.rs
    └── server.rs    # Axum Web UI サーバー
static/
└── dashboard.html   # ダッシュボード (組み込み SPA)
```
