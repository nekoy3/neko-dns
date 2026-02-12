use rand::Rng;
use crate::config::NekoCommentConfig;

/// 🐱 neko-dns の隠し味 - ADDITIONALセクションにネコのひとことを仕込む
pub struct NekoComment {
    enabled: bool,
    messages: Vec<&'static str>,
}

const NEKO_MESSAGES: &[&str] = &[
    // 日本語ネコ語
    "にゃー。DNSってうまいの？",
    "キャッシュヒットにゃ！ (ΦωΦ)",
    "このクエリ、さっきも見たにゃ",
    "上流に聞いてきたにゃー",
    "ゴロゴロ... DNS解決完了にゃ",
    "お魚くわえたドメイン名にゃ",
    "毛づくろい中... あ、レスポンス返すにゃ",
    "にゃんでそんなドメイン聞くにゃ？",
    "TTL錬金術でちょっと長持ちにゃ",
    "夜行性なので深夜のクエリ大歓迎にゃ",
    // 英語ネコ
    "meow. resolving your queries since 2026",
    "purrfect cache hit! =^.^=",
    "i can haz DNS resolution?",
    "404 cat not found... just kidding, here's your answer",
    "this response was paw-cessed by neko-dns",
    "DNS is just cats all the way down",
    "trust me, this upstream is purr-liable",
    "cached with love by a digital cat",
    // ネコ雑学
    "fun fact: cats sleep 16 hours, neko-dns sleeps 0",
    "neko-dns has 9 lives... err, 4 upstreams",
    "the internet was made for cats. and DNS.",
    // アスキーアート的な
    "/\\_/\\ meow~",
    "(=^-^=) resolved!",
    "~(=^..^) nyan~",
    ">{^_^}< query complete!",
    // 季節もの・時間帯
    "深夜のDNS職人、ここにいるにゃ",
    "もう寝たら？...にゃんて",
];

impl NekoComment {
    pub fn new(config: &NekoCommentConfig) -> Self {
        Self {
            enabled: config.enabled,
            messages: NEKO_MESSAGES.to_vec(),
        }
    }

    /// ランダムなひとことを取得
    pub fn get_comment(&self) -> Option<&str> {
        if !self.enabled {
            return None;
        }
        let mut rng = rand::thread_rng();
        Some(self.messages[rng.gen_range(0..self.messages.len())])
    }

    /// ADDITIONALセクション用のTXTレコードバイナリを生成
    /// name: "neko-dns.comment." の TXT レコード
    pub fn build_additional_txt(&self) -> Option<Vec<u8>> {
        let comment = self.get_comment()?;
        let mut record = Vec::new();

        // Name: "neko-dns.comment." encoded
        // neko-dns = 8 bytes label
        // comment  = 7 bytes label
        record.push(8);
        record.extend_from_slice(b"neko-dns");
        record.push(7);
        record.extend_from_slice(b"comment");
        record.push(0); // root

        // Type: TXT (16)
        record.extend_from_slice(&16u16.to_be_bytes());
        // Class: CH (Chaosnet, class 3) - 慣例的にメタ情報はCHクラス
        record.extend_from_slice(&3u16.to_be_bytes());
        // TTL: 0 (キャッシュしない)
        record.extend_from_slice(&0u32.to_be_bytes());

        // RDATA: TXT format = length-prefixed strings
        let comment_bytes = comment.as_bytes();
        // TXTは255バイト以下の文字列を複数格納できる
        // 1つの文字列として格納
        let mut rdata = Vec::new();
        // 長い場合は分割
        for chunk in comment_bytes.chunks(255) {
            rdata.push(chunk.len() as u8);
            rdata.extend_from_slice(chunk);
        }

        // RDLENGTH
        record.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        record.extend(rdata);

        Some(record)
    }
}
