use crate::config::EdnsConfig;
use tracing::debug;

/// EDNS Extension Handler
///
/// EDNS0 OPT レコード (RFC 6891) に独自オプションコードを追加。
/// クエリに「mood=curious」みたいなメタデータを載せられる。
/// クライアントが対応してなくても無視されるだけ。
///
/// 使用するオプションコード: 65001-65534 (Private Use range)

#[derive(Debug, Clone)]
pub struct EdnsMeta {
    pub options: Vec<(u16, Vec<u8>)>,
}

pub struct EdnsHandler {
    config: EdnsConfig,
}

impl EdnsHandler {
    pub fn new(config: &EdnsConfig) -> Self {
        Self {
            config: config.clone(),
        }
    }

    /// Extract custom EDNS options from a DNS packet
    pub fn extract_options(&self, packet: &[u8]) -> Option<EdnsMeta> {
        if !self.config.enabled {
            return None;
        }

        // Find OPT record in additional section
        let parsed = crate::dns::packet::parse_packet(packet).ok()?;
        
        for record in &parsed.additionals {
            if record.rtype == crate::dns::types::RecordType::OPT {
                // Parse EDNS options from rdata
                let options = self.parse_edns_options(&record.rdata);
                if !options.is_empty() {
                    return Some(EdnsMeta { options });
                }
            }
        }

        None
    }

    /// Parse EDNS option pairs from OPT rdata
    fn parse_edns_options(&self, rdata: &[u8]) -> Vec<(u16, Vec<u8>)> {
        let mut options = Vec::new();
        let mut offset = 0;

        while offset + 4 <= rdata.len() {
            let code = u16::from_be_bytes([rdata[offset], rdata[offset + 1]]);
            let length = u16::from_be_bytes([rdata[offset + 2], rdata[offset + 3]]) as usize;
            offset += 4;

            if offset + length > rdata.len() {
                break;
            }

            let data = rdata[offset..offset + length].to_vec();
            offset += length;

            // Only collect our custom options
            if code >= 65001 && code <= 65534 {
                debug!("Found custom EDNS option: code={}, len={}", code, length);
                options.push((code, data));
            }
        }

        options
    }

    /// Build an EDNS OPT record with custom options
    pub fn build_opt_record(&self, options: &[(u16, &[u8])]) -> Vec<u8> {
        let mut rdata = Vec::new();
        for (code, data) in options {
            rdata.extend_from_slice(&code.to_be_bytes());
            rdata.extend_from_slice(&(data.len() as u16).to_be_bytes());
            rdata.extend_from_slice(data);
        }

        let mut record = Vec::new();
        // OPT record: name=root(0), type=OPT(41), udp_size=4096, extended_rcode=0, version=0, flags=0
        record.push(0); // root name
        record.extend_from_slice(&41u16.to_be_bytes()); // TYPE = OPT
        record.extend_from_slice(&4096u16.to_be_bytes()); // CLASS = UDP payload size
        record.extend_from_slice(&0u32.to_be_bytes()); // TTL = extended RCODE + version + flags
        record.extend_from_slice(&(rdata.len() as u16).to_be_bytes()); // RDLENGTH
        record.extend_from_slice(&rdata);

        record
    }
}
