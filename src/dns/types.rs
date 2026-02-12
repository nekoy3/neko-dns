/// DNS record types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum RecordType {
    A = 1,
    NS = 2,
    CNAME = 5,
    SOA = 6,
    PTR = 12,
    MX = 15,
    TXT = 16,
    AAAA = 28,
    SRV = 33,
    OPT = 41,     // EDNS
    ANY = 255,
    Unknown(u16),
}

impl From<u16> for RecordType {
    fn from(v: u16) -> Self {
        match v {
            1 => RecordType::A,
            2 => RecordType::NS,
            5 => RecordType::CNAME,
            6 => RecordType::SOA,
            12 => RecordType::PTR,
            15 => RecordType::MX,
            16 => RecordType::TXT,
            28 => RecordType::AAAA,
            33 => RecordType::SRV,
            41 => RecordType::OPT,
            255 => RecordType::ANY,
            other => RecordType::Unknown(other),
        }
    }
}

impl RecordType {
    pub fn to_u16(&self) -> u16 {
        match self {
            RecordType::A => 1,
            RecordType::NS => 2,
            RecordType::CNAME => 5,
            RecordType::SOA => 6,
            RecordType::PTR => 12,
            RecordType::MX => 15,
            RecordType::TXT => 16,
            RecordType::AAAA => 28,
            RecordType::SRV => 33,
            RecordType::OPT => 41,
            RecordType::ANY => 255,
            RecordType::Unknown(v) => *v,
        }
    }

    pub fn name(&self) -> String {
        match self {
            RecordType::A => "A".into(),
            RecordType::NS => "NS".into(),
            RecordType::CNAME => "CNAME".into(),
            RecordType::SOA => "SOA".into(),
            RecordType::PTR => "PTR".into(),
            RecordType::MX => "MX".into(),
            RecordType::TXT => "TXT".into(),
            RecordType::AAAA => "AAAA".into(),
            RecordType::SRV => "SRV".into(),
            RecordType::OPT => "OPT".into(),
            RecordType::ANY => "ANY".into(),
            RecordType::Unknown(v) => format!("TYPE{}", v),
        }
    }
}

/// DNS response codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ResponseCode {
    NoError = 0,
    FormErr = 1,
    ServFail = 2,
    NxDomain = 3,
    NotImp = 4,
    Refused = 5,
}

impl From<u8> for ResponseCode {
    fn from(v: u8) -> Self {
        match v {
            0 => ResponseCode::NoError,
            1 => ResponseCode::FormErr,
            2 => ResponseCode::ServFail,
            3 => ResponseCode::NxDomain,
            4 => ResponseCode::NotImp,
            5 => ResponseCode::Refused,
            _ => ResponseCode::ServFail,
        }
    }
}

/// DNS class
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum DnsClass {
    IN = 1,
    CH = 3,
    HS = 4,
    ANY = 255,
    Unknown(u16),
}

impl From<u16> for DnsClass {
    fn from(v: u16) -> Self {
        match v {
            1 => DnsClass::IN,
            3 => DnsClass::CH,
            4 => DnsClass::HS,
            255 => DnsClass::ANY,
            other => DnsClass::Unknown(other),
        }
    }
}

impl DnsClass {
    pub fn to_u16(&self) -> u16 {
        match self {
            DnsClass::IN => 1,
            DnsClass::CH => 3,
            DnsClass::HS => 4,
            DnsClass::ANY => 255,
            DnsClass::Unknown(v) => *v,
        }
    }
}
