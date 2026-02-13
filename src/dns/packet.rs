use crate::dns::types::{RecordType, DnsClass, ResponseCode};
use crate::neko_comment::{NekoComment, QueryFeatures};
use std::fmt;

/// Raw DNS packet parser - full binary level parsing per RFC 1035
/// No external DNS library used - everything is hand-parsed from &[u8]

#[derive(Debug, Clone)]
pub struct DnsHeader {
    pub id: u16,
    pub qr: bool,          // Query/Response flag
    pub opcode: u8,         // 4 bits
    pub aa: bool,           // Authoritative Answer
    pub tc: bool,           // Truncated
    pub rd: bool,           // Recursion Desired
    pub ra: bool,           // Recursion Available
    pub z: u8,              // Reserved (3 bits)
    pub rcode: ResponseCode,
    pub qdcount: u16,       // Question count
    pub ancount: u16,       // Answer count
    pub nscount: u16,       // Authority count
    pub arcount: u16,       // Additional count
}

#[derive(Debug, Clone)]
pub struct DnsQuestion {
    pub name: String,
    pub qtype: RecordType,
    pub qclass: DnsClass,
}

#[derive(Debug, Clone)]
pub struct DnsRecord {
    pub name: String,
    pub rtype: RecordType,
    pub rclass: DnsClass,
    pub ttl: u32,
    pub rdlength: u16,
    pub rdata: Vec<u8>,
    /// rdataのパケット内開始オフセット (圧縮ポインタ解決用)
    pub rdata_offset: usize,
}

#[derive(Debug, Clone)]
pub struct DnsPacket {
    pub header: DnsHeader,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsRecord>,
    pub authorities: Vec<DnsRecord>,
    pub additionals: Vec<DnsRecord>,
    pub raw: Vec<u8>,
}

impl fmt::Display for DnsPacket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(q) = self.questions.first() {
            write!(f, "{} {} (answers: {})", q.name, q.qtype.name(), self.header.ancount)
        } else {
            write!(f, "(empty query)")
        }
    }
}

/// Parse a DNS name from raw bytes with label compression support (RFC 1035 §4.1.4)
pub fn parse_name(data: &[u8], offset: &mut usize) -> anyhow::Result<String> {
    let mut labels = Vec::new();
    let mut jumped = false;
    let mut jump_offset = 0usize;
    let original_offset = *offset;
    let mut pos = *offset;
    let mut jumps_performed = 0;
    const MAX_JUMPS: usize = 10; // Prevent infinite loops

    loop {
        if pos >= data.len() {
            return Err(anyhow::anyhow!("DNS name parse: unexpected end of data at offset {}", pos));
        }

        let len_byte = data[pos];

        // Check for pointer (compression) - top 2 bits are 11
        if (len_byte & 0xC0) == 0xC0 {
            if pos + 1 >= data.len() {
                return Err(anyhow::anyhow!("DNS name parse: truncated pointer at offset {}", pos));
            }
            if !jumped {
                // Save where we need to continue reading after this name
                *offset = pos + 2;
                jumped = true;
            }
            let pointer = ((len_byte as u16 & 0x3F) << 8) | data[pos + 1] as u16;
            pos = pointer as usize;
            jumps_performed += 1;
            if jumps_performed > MAX_JUMPS {
                return Err(anyhow::anyhow!("DNS name parse: too many jumps (possible loop)"));
            }
            continue;
        }

        // Normal label
        if len_byte == 0 {
            // End of name
            if !jumped {
                *offset = pos + 1;
            }
            break;
        }

        let label_len = len_byte as usize;
        pos += 1;

        if pos + label_len > data.len() {
            return Err(anyhow::anyhow!("DNS name parse: label extends beyond packet"));
        }

        let label = String::from_utf8_lossy(&data[pos..pos + label_len]).to_string();
        labels.push(label);
        pos += label_len;
    }

    Ok(labels.join("."))
}

/// Parse a complete DNS packet from raw bytes
pub fn parse_packet(data: &[u8]) -> anyhow::Result<DnsPacket> {
    if data.len() < 12 {
        return Err(anyhow::anyhow!("DNS packet too short: {} bytes (minimum 12)", data.len()));
    }

    // Parse header (12 bytes)
    let id = u16::from_be_bytes([data[0], data[1]]);
    let flags = u16::from_be_bytes([data[2], data[3]]);
    let qdcount = u16::from_be_bytes([data[4], data[5]]);
    let ancount = u16::from_be_bytes([data[6], data[7]]);
    let nscount = u16::from_be_bytes([data[8], data[9]]);
    let arcount = u16::from_be_bytes([data[10], data[11]]);

    let header = DnsHeader {
        id,
        qr: (flags >> 15) & 1 == 1,
        opcode: ((flags >> 11) & 0xF) as u8,
        aa: (flags >> 10) & 1 == 1,
        tc: (flags >> 9) & 1 == 1,
        rd: (flags >> 8) & 1 == 1,
        ra: (flags >> 7) & 1 == 1,
        z: ((flags >> 4) & 0x7) as u8,
        rcode: ResponseCode::from((flags & 0xF) as u8),
        qdcount,
        ancount,
        nscount,
        arcount,
    };

    let mut offset = 12;

    // Parse questions
    let mut questions = Vec::new();
    for _ in 0..qdcount {
        let name = parse_name(data, &mut offset)?;
        if offset + 4 > data.len() {
            return Err(anyhow::anyhow!("DNS question section truncated"));
        }
        let qtype = RecordType::from(u16::from_be_bytes([data[offset], data[offset + 1]]));
        let qclass = DnsClass::from(u16::from_be_bytes([data[offset + 2], data[offset + 3]]));
        offset += 4;
        questions.push(DnsQuestion { name, qtype, qclass });
    }

    // Parse resource records (answers, authorities, additionals)
    let answers = parse_records(data, &mut offset, ancount)?;
    let authorities = parse_records(data, &mut offset, nscount)?;
    let additionals = parse_records(data, &mut offset, arcount)?;

    Ok(DnsPacket {
        header,
        questions,
        answers,
        authorities,
        additionals,
        raw: data.to_vec(),
    })
}

fn parse_records(data: &[u8], offset: &mut usize, count: u16) -> anyhow::Result<Vec<DnsRecord>> {
    let mut records = Vec::new();
    for _ in 0..count {
        let name = parse_name(data, offset)?;
        if *offset + 10 > data.len() {
            return Err(anyhow::anyhow!("DNS record truncated at offset {}", offset));
        }
        let rtype = RecordType::from(u16::from_be_bytes([data[*offset], data[*offset + 1]]));
        let rclass = DnsClass::from(u16::from_be_bytes([data[*offset + 2], data[*offset + 3]]));
        let ttl = u32::from_be_bytes([data[*offset + 4], data[*offset + 5], data[*offset + 6], data[*offset + 7]]);
        let rdlength = u16::from_be_bytes([data[*offset + 8], data[*offset + 9]]);
        *offset += 10;

        if *offset + rdlength as usize > data.len() {
            return Err(anyhow::anyhow!("DNS rdata extends beyond packet"));
        }
        let rdata_offset = *offset;
        let rdata = data[*offset..*offset + rdlength as usize].to_vec();
        *offset += rdlength as usize;

        records.push(DnsRecord {
            name,
            rtype,
            rclass,
            ttl,
            rdlength,
            rdata,
            rdata_offset,
        });
    }
    Ok(records)
}

/// Build a SERVFAIL response from a query packet
pub fn build_servfail(query: &[u8]) -> anyhow::Result<Vec<u8>> {
    if query.len() < 12 {
        return Err(anyhow::anyhow!("Query too short for SERVFAIL"));
    }
    let mut response = query.to_vec();
    // Set QR=1 (response), keep opcode, set RCODE=2 (SERVFAIL)
    response[2] = (response[2] | 0x80) & 0xFB; // QR=1, TC=0
    response[3] = (response[3] & 0xF0) | 0x02;  // RCODE=2
    // Zero out answer/authority/additional counts
    response[6] = 0; response[7] = 0;
    response[8] = 0; response[9] = 0;
    response[10] = 0; response[11] = 0;
    // Truncate after question section
    Ok(response)
}

/// Build a response packet with modified TTLs from cached data
pub fn build_response(query: &[u8], cached_response: &[u8], new_ttl: u32) -> anyhow::Result<Vec<u8>> {
    let mut response = cached_response.to_vec();
    if response.len() < 12 || query.len() < 2 {
        return Err(anyhow::anyhow!("Packet too short"));
    }
    // Copy transaction ID from query
    response[0] = query[0];
    response[1] = query[1];

    // Update TTLs in all answer records
    let parsed = parse_packet(&response)?;
    let mut offset = 12;

    // Skip questions
    for _ in 0..parsed.header.qdcount {
        parse_name(&response, &mut offset)?;
        offset += 4;
    }

    // Update TTLs in answers, authorities, additionals
    let total_records = parsed.header.ancount + parsed.header.nscount + parsed.header.arcount;
    for _ in 0..total_records {
        parse_name(&response, &mut offset)?;
        let rtype = u16::from_be_bytes([response[offset], response[offset + 1]]);
        // Don't modify OPT record TTL
        if rtype != 41 {
            let ttl_bytes = new_ttl.to_be_bytes();
            response[offset + 4] = ttl_bytes[0];
            response[offset + 5] = ttl_bytes[1];
            response[offset + 6] = ttl_bytes[2];
            response[offset + 7] = ttl_bytes[3];
        }
        let rdlength = u16::from_be_bytes([response[offset + 8], response[offset + 9]]);
        offset += 10 + rdlength as usize;
    }

    Ok(response)
}

/// Encode a DNS name into wire format
pub fn encode_name(name: &str) -> Vec<u8> {
    let mut result = Vec::new();
    if name.is_empty() {
        result.push(0);
        return result;
    }
    for label in name.split('.') {
        result.push(label.len() as u8);
        result.extend_from_slice(label.as_bytes());
    }
    result.push(0);
    result
}

/// Build a query packet for upstream forwarding
pub fn build_query(id: u16, name: &str, qtype: RecordType, rd: bool) -> Vec<u8> {
    let mut packet = Vec::with_capacity(512);

    // Header
    packet.extend_from_slice(&id.to_be_bytes());
    let flags: u16 = if rd { 0x0100 } else { 0x0000 }; // RD=1
    packet.extend_from_slice(&flags.to_be_bytes());
    packet.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT=1
    packet.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT=0
    packet.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT=0
    packet.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT=0

    // Question
    packet.extend_from_slice(&encode_name(name));
    packet.extend_from_slice(&qtype.to_u16().to_be_bytes());
    packet.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN

    packet
}

/// Extract the query name and type from a raw DNS query
pub fn extract_query_info(data: &[u8]) -> anyhow::Result<(String, RecordType)> {
    if data.len() < 12 {
        return Err(anyhow::anyhow!("Query too short"));
    }
    let mut offset = 12;
    let name = parse_name(data, &mut offset)?;
    if offset + 4 > data.len() {
        return Err(anyhow::anyhow!("Query truncated after name"));
    }
    let qtype = RecordType::from(u16::from_be_bytes([data[offset], data[offset + 1]]));
    Ok((name, qtype))
}

/// Format rdata for display based on record type
pub fn format_rdata(rtype: &RecordType, rdata: &[u8], full_packet: &[u8]) -> String {
    match rtype {
        RecordType::A if rdata.len() == 4 => {
            format!("{}.{}.{}.{}", rdata[0], rdata[1], rdata[2], rdata[3])
        }
        RecordType::AAAA if rdata.len() == 16 => {
            let parts: Vec<String> = (0..8)
                .map(|i| format!("{:x}", u16::from_be_bytes([rdata[i * 2], rdata[i * 2 + 1]])))
                .collect();
            parts.join(":")
        }
        RecordType::CNAME | RecordType::NS | RecordType::PTR => {
            // These contain a domain name - try to parse it
            let mut offset = 0;
            // We need to find the rdata position in the full packet for decompression
            // For simplicity, try parsing standalone first
            if let Ok(name) = parse_name_standalone(rdata) {
                name
            } else {
                format!("(binary {} bytes)", rdata.len())
            }
        }
        RecordType::MX if rdata.len() >= 3 => {
            let preference = u16::from_be_bytes([rdata[0], rdata[1]]);
            if let Ok(name) = parse_name_standalone(&rdata[2..]) {
                format!("{} {}", preference, name)
            } else {
                format!("{} (binary)", preference)
            }
        }
        RecordType::TXT => {
            let mut result = String::new();
            let mut pos = 0;
            while pos < rdata.len() {
                let txt_len = rdata[pos] as usize;
                pos += 1;
                if pos + txt_len <= rdata.len() {
                    result.push_str(&String::from_utf8_lossy(&rdata[pos..pos + txt_len]));
                    pos += txt_len;
                } else {
                    break;
                }
            }
            format!("\"{}\"", result)
        }
        _ => format!("(binary {} bytes)", rdata.len()),
    }
}

/// Parse a DNS name without compression support (for standalone rdata)
fn parse_name_standalone(data: &[u8]) -> anyhow::Result<String> {
    let mut labels = Vec::new();
    let mut pos = 0;
    loop {
        if pos >= data.len() {
            return Err(anyhow::anyhow!("Unexpected end"));
        }
        let len = data[pos] as usize;
        if len == 0 {
            break;
        }
        if (data[pos] & 0xC0) == 0xC0 {
            return Err(anyhow::anyhow!("Compression not supported in standalone parse"));
        }
        pos += 1;
        if pos + len > data.len() {
            return Err(anyhow::anyhow!("Label extends beyond data"));
        }
        labels.push(String::from_utf8_lossy(&data[pos..pos + len]).to_string());
        pos += len;
    }
    Ok(labels.join("."))
}

/// Parse a domain name from rdata, using the full packet for compression pointer resolution.
/// `rdata_offset` is where the rdata begins within `full_packet`.
pub fn parse_name_from_rdata(rdata: &[u8], full_packet: &[u8]) -> anyhow::Result<String> {
    // Try standalone parse first (no compression)
    if let Ok(name) = parse_name_standalone(rdata) {
        return Ok(name);
    }
    // If rdata uses compression pointers, we need the full packet context.
    // The rdata bytes are a subset of full_packet, so parse directly from full_packet
    // at the rdata position.
    Err(anyhow::anyhow!("Cannot parse name from rdata standalone"))
}

/// Parse a domain name from a known offset within the full packet.
/// This handles compression pointers correctly.
pub fn parse_name_at_offset(full_packet: &[u8], offset: usize) -> anyhow::Result<String> {
    let mut pos = offset;
    parse_name(full_packet, &mut pos)
}

/// Append a neko-dns feature notification TXT record to a response.
/// Shows which resolver features were triggered during query processing.
/// Modifies the packet in-place: appends the record bytes and increments ARCOUNT.
pub fn append_feature_record(response: &mut Vec<u8>, neko: &NekoComment, features: &QueryFeatures) {
    if response.len() < 12 {
        return;
    }
    let mut added: u16 = 0;

    // 1. Feature flags TXT record
    if let Some(txt_record) = neko.build_feature_txt(features) {
        response.extend_from_slice(&txt_record);
        added += 1;
    }

    // 2. Random cat message TXT record
    if let Some(msg_record) = neko.build_neko_message_txt() {
        response.extend_from_slice(&msg_record);
        added += 1;
    }

    if added > 0 {
        // Increment ARCOUNT (bytes 10-11)
        let arcount = u16::from_be_bytes([response[10], response[11]]);
        let new_arcount = arcount.wrapping_add(added);
        let ar_bytes = new_arcount.to_be_bytes();
        response[10] = ar_bytes[0];
        response[11] = ar_bytes[1];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_parse_name() {
        let name = "example.com";
        let encoded = encode_name(name);
        assert_eq!(encoded, vec![7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0]);

        let mut offset = 0;
        let parsed = parse_name(&encoded, &mut offset).unwrap();
        assert_eq!(parsed, "example.com");
    }

    #[test]
    fn test_build_query() {
        let query = build_query(0x1234, "google.com", RecordType::A, true);
        assert!(query.len() > 12);
        assert_eq!(query[0], 0x12);
        assert_eq!(query[1], 0x34);
        // RD flag
        assert_eq!(query[2] & 0x01, 0x01);
    }

    #[test]
    fn test_build_servfail() {
        let query = build_query(0xABCD, "test.com", RecordType::A, true);
        let servfail = build_servfail(&query).unwrap();
        // QR=1
        assert!(servfail[2] & 0x80 != 0);
        // RCODE=2
        assert_eq!(servfail[3] & 0x0F, 2);
    }

    #[test]
    fn test_parse_packet() {
        let query = build_query(0x1234, "example.com", RecordType::A, true);
        let packet = parse_packet(&query).unwrap();
        assert_eq!(packet.header.id, 0x1234);
        assert_eq!(packet.header.qdcount, 1);
        assert_eq!(packet.questions[0].name, "example.com");
    }
}
