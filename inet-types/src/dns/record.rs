use crate::dns::DNSString;
use bytepack::{ByteOrder::BigEndian, FromBytestream, StreamReader, StreamWriter, ToBytestream};
use bytepack::{BytestreamReader, BytestreamWriter};
use std::fmt::Display;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DNSResourceRecord {
    pub name: DNSString,
    pub typ: DNSType,
    pub class: DNSClass,
    pub ttl: i32,
    // rdata (len = u16)
    pub rdata: Vec<u8>,
}

impl ToBytestream for DNSResourceRecord {
    type Error = std::io::Error;
    fn to_bytestream(&self, bytestream: &mut BytestreamWriter) -> Result<(), Self::Error> {
        self.name.to_bytestream(bytestream)?;

        self.typ.to_raw().write_to(bytestream, BigEndian)?;
        self.class.to_raw().write_to(bytestream, BigEndian)?;
        self.ttl.write_to(bytestream, BigEndian)?;

        (self.rdata.len() as u16).write_to(bytestream, BigEndian)?;
        for byte in &self.rdata {
            byte.write_to(bytestream, BigEndian)?;
        }

        Ok(())
    }
}

impl FromBytestream for DNSResourceRecord {
    type Error = std::io::Error;
    fn from_bytestream(bytestream: &mut BytestreamReader) -> Result<Self, Self::Error> {
        let name = DNSString::from_bytestream(bytestream)?;

        let typ = DNSType::from_raw(u16::read_from(bytestream, BigEndian)?).unwrap();
        let class = DNSClass::from_raw(u16::read_from(bytestream, BigEndian)?).unwrap();
        let ttl = i32::read_from(bytestream, BigEndian)?;
        let len = u16::read_from(bytestream, BigEndian)? as usize;
        let mut rdata = Vec::with_capacity(len);
        for _ in 0..len {
            rdata.push(u8::read_from(bytestream, BigEndian)?);
        }

        Ok(DNSResourceRecord {
            name,
            typ,
            class,
            ttl,
            rdata,
        })
    }
}

impl DNSResourceRecord {
    #[must_use]
    pub fn as_addr(&self) -> IpAddr {
        match self.typ {
            DNSType::A => {
                let mut bytes = [0u8; 4];
                bytes[..4].copy_from_slice(&self.rdata[..4]);
                IpAddr::from(bytes)
            }
            DNSType::AAAA => {
                let mut bytes = [0u8; 16];
                bytes[..16].copy_from_slice(&self.rdata[..16]);
                IpAddr::from(bytes)
            }
            _ => unimplemented!(),
        }
    }

    fn rdata_fmt(&self) -> String {
        match self.typ {
            DNSType::A => {
                format!(
                    "{}",
                    Ipv4Addr::new(self.rdata[0], self.rdata[1], self.rdata[2], self.rdata[3])
                )
            }
            DNSType::AAAA => {
                let mut octets = [0u8; 16];
                octets[..self.rdata.len()].copy_from_slice(&self.rdata);

                format!("{}", Ipv6Addr::from(octets))
            }
            DNSType::NS | DNSType::CNAME | DNSType::PTR => {
                let dnsstring = DNSString::from_buffer(self.rdata.clone())
                    .expect("Failed to reparse DNS String");
                dnsstring.into_inner()
            }
            _ => String::new(),
        }
    }
}

impl Display for DNSResourceRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} {} {} {} {}",
            *self.name,
            self.ttl,
            self.class,
            self.typ,
            self.rdata_fmt()
        )
    }
}

// # DNSType

primitve_enum_repr! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub enum DNSType {
        type Repr = u16;

        A = 1,
        AAAA = 28,
        AFSDB = 18,
        APL = 42,
        CAA = 257,
        CDNSKEY = 60,
        CDS = 59,
        CERT = 37,
        CNAME = 5,
        CSYNC = 62,
        DHCID = 49,
        DLV = 32769,
        DNAME = 39,
        DNSKEY = 48,
        DS = 43,
        EUI48 = 108,
        EUI64 = 109,
        HINFO = 13,
        HIP = 55,
        HTTPS = 65,
        IPSECKEY = 45,
        KEY = 25,
        KX = 36,
        LOC = 29,
        MX = 15,
        NAPTR = 35,
        NS = 2,
        NSEC = 47,
        NSEC3 = 50,
        NSEC3PARAM = 51,
        OPENPGPKEY = 61,
        PTR = 12,
        RRSIG = 46,
        RP = 17,
        SIG = 24,
        SMIMEA = 53,
        SOA = 6,
        SRV = 33,
        SSHFP = 44,
        SVCB = 64,
        TA = 32768,
        TKEY = 249,
        TLSA = 52,
        TSIG = 250,
        TXT = 16,
        URI = 256,
        ZONEMD = 63,
    };
}

impl FromStr for DNSType {
    type Err = &'static str;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match &s.to_uppercase()[..] {
            "A" => Ok(Self::A),
            "AAAA" => Ok(Self::AAAA),
            "SOA" => Ok(Self::SOA),
            "NS" => Ok(Self::NS),
            "PTR" => Ok(Self::PTR),
            _ => Err("Not supported"),
        }
    }
}

impl Display for DNSType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DNSType::A => write!(f, "A"),
            DNSType::AAAA => write!(f, "AAAA"),
            DNSType::NS => write!(f, "NS"),
            DNSType::CNAME => write!(f, "CNAME"),
            DNSType::PTR => write!(f, "PTR"),
            // DNSType::A => write!(f, "A"),
            // DNSType::A => write!(f, "A"),
            default => write!(f, "{default:?}"),
        }
    }
}

// # DNSClass

primitve_enum_repr! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub enum DNSClass {
        type Repr = u16;

        Internet = 1,
        Chaos = 3,
        Hesoid = 4,
        QClassNone = 254,
        QClassAny = 255,
    };
}

impl FromStr for DNSClass {
    type Err = &'static str;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match &s.to_uppercase()[..] {
            "IN" => Ok(DNSClass::Internet),
            "CH" => Ok(DNSClass::Chaos),
            "HS" => Ok(DNSClass::Hesoid),
            "QN" => Ok(DNSClass::QClassNone),
            "QA" => Ok(DNSClass::QClassAny),
            _ => Err("Not supported"),
        }
    }
}

impl Display for DNSClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DNSClass::Internet => write!(f, "IN"),
            DNSClass::Chaos => write!(f, "CH"),
            DNSClass::Hesoid => write!(f, "HE"),
            DNSClass::QClassNone => write!(f, "QN"),
            DNSClass::QClassAny => write!(f, "QA"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DNSSOAResourceRecord {
    pub name: DNSString,
    // type,
    pub class: DNSClass,
    pub ttl: i32,
    pub mname: DNSString,
    pub rname: DNSString,
    pub serial: i32,
    pub refresh: i32,
    pub retry: i32,
    pub expire: i32,
    pub minimum: i32,
}
