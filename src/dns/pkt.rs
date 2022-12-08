#![allow(unused)]
use super::DNSString;
use crate::common::{split_off_front, FromBytestreamDepc, IntoBytestreamDepc};
use bytestream::{ByteOrder::*, StreamReader, StreamWriter};
use std::{
    fmt::Display,
    io::Cursor,
    net::{Ipv4Addr, Ipv6Addr},
    ops::{Deref, DerefMut},
};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DNSMessage {
    pub transaction: u16,
    // # Headers
    pub qr: bool,
    pub opcode: DNSOpCode,
    pub aa: bool,
    pub tc: bool,
    pub rd: bool,
    pub ra: bool,
    pub rcode: DNSResponseCode,
    // [u16; 4] lengths of all 4 question sections.
    // # Questions
    pub questions: Vec<DNSQuestion>,
    // # Anwsers
    pub anwsers: Vec<DNSResourceRecord>,
    // # Authority
    pub auths: Vec<DNSResourceRecord>,
    // # Additional
    pub additional: Vec<DNSResourceRecord>,
}

impl DNSMessage {
    pub fn question_a(transaction: u16, name: impl Into<DNSString>) -> Self {
        Self {
            transaction,
            qr: false,
            opcode: DNSOpCode::Query,
            aa: false,
            tc: false,
            rd: false,
            ra: false,

            rcode: DNSResponseCode::NoError,
            questions: vec![DNSQuestion {
                qname: name.into(),
                qtyp: DNSType::A,
                qclass: DNSClass::Internet,
            }],
            anwsers: Vec::new(),
            auths: Vec::new(),
            additional: Vec::new(),
        }
    }

    pub fn question_aaaa(transaction: u16, name: impl Into<DNSString>) -> Self {
        Self {
            transaction,
            qr: false,
            opcode: DNSOpCode::Query,
            aa: false,
            tc: false,
            rd: false,
            ra: false,

            rcode: DNSResponseCode::NoError,
            questions: vec![DNSQuestion {
                qname: name.into(),
                qtyp: DNSType::AAAA,
                qclass: DNSClass::Internet,
            }],
            anwsers: Vec::new(),
            auths: Vec::new(),
            additional: Vec::new(),
        }
    }

    pub fn response(&self) -> impl Iterator<Item = &DNSResourceRecord> {
        self.anwsers
            .iter()
            .chain(self.auths.iter())
            .chain(self.additional.iter())
    }
}

impl IntoBytestreamDepc for DNSMessage {
    type Error = std::io::Error;
    fn into_bytestream(&self, bytestream: &mut Vec<u8>) -> Result<(), Self::Error> {
        self.transaction.write_to(bytestream, BigEndian)?;

        let mut b0 = self.opcode.to_raw() << 3;
        if self.qr {
            b0 |= 0b1000_0000
        }
        if self.aa {
            b0 |= 0b0000_0100
        }
        if self.tc {
            b0 |= 0b0000_0010
        }
        if self.rd {
            b0 |= 0b0000_0001
        }
        b0.write_to(bytestream, BigEndian)?;

        let mut b1 = self.rcode.to_raw() as u8;
        if self.ra {
            b1 |= 0b1000_0000
        }
        b1.write_to(bytestream, BigEndian)?;

        (self.questions.len() as u16).write_to(bytestream, BigEndian)?;
        (self.anwsers.len() as u16).write_to(bytestream, BigEndian)?;
        (self.auths.len() as u16).write_to(bytestream, BigEndian)?;
        (self.additional.len() as u16).write_to(bytestream, BigEndian)?;

        for q in &self.questions {
            q.into_bytestream(bytestream)?
        }
        for a in &self.anwsers {
            a.into_bytestream(bytestream)?
        }
        for a in &self.auths {
            a.into_bytestream(bytestream)?
        }
        for a in &self.additional {
            a.into_bytestream(bytestream)?
        }

        Ok(())
    }
}

impl FromBytestreamDepc for DNSMessage {
    type Error = std::io::Error;
    fn from_bytestream(bytestream: Vec<u8>) -> Result<Self, Self::Error> {
        let mut cursor = Cursor::new(bytestream);
        let transaction = u16::read_from(&mut cursor, BigEndian)?;
        let b0 = u8::read_from(&mut cursor, BigEndian)?;
        let b1 = u8::read_from(&mut cursor, BigEndian)?;

        let qr = (0b1000_0000 & b0) != 0;
        let aa = (0b0000_0100 & b0) != 0;
        let tc = (0b0000_0010 & b0) != 0;
        let rd = (0b0000_0001 & b0) != 0;
        let opcode = DNSOpCode::from_raw((b0 >> 3) & 0b1111).unwrap();

        let ra = (0b1000_0000 & b1) != 0;
        let rcode = DNSResponseCode::from_raw((b1 & 0b1111) as u16).unwrap();

        let nquestions = u16::read_from(&mut cursor, BigEndian)?;
        let nanwsers = u16::read_from(&mut cursor, BigEndian)?;
        let nauth = u16::read_from(&mut cursor, BigEndian)?;
        let nadditional = u16::read_from(&mut cursor, BigEndian)?;

        let pos = cursor.position() as usize;
        let mut bytestream = split_off_front(cursor.into_inner(), pos);
        let mut questions = Vec::new();

        // println!("{} {} {} {}", nquestions, nanwsers, nauth, nadditional);

        for _ in 0..nquestions {
            let (v, mem) = <(DNSQuestion, Vec<u8>)>::from_bytestream(bytestream)?;
            questions.push(v);
            bytestream = mem;
        }

        // println!("> done q");

        let mut anwsers = Vec::new();
        for _ in 0..nanwsers {
            let (v, mem) = <(DNSResourceRecord, Vec<u8>)>::from_bytestream(bytestream)?;
            anwsers.push(v);
            bytestream = mem;
        }

        // println!("> done a");

        let mut auths = Vec::new();
        for _ in 0..nauth {
            let (v, mem) = <(DNSResourceRecord, Vec<u8>)>::from_bytestream(bytestream)?;
            auths.push(v);
            bytestream = mem;
        }

        let mut additional = Vec::new();
        for _ in 0..nadditional {
            let (v, mem) = <(DNSResourceRecord, Vec<u8>)>::from_bytestream(bytestream)?;
            additional.push(v);
            bytestream = mem;
        }

        Ok(DNSMessage {
            transaction,
            qr,
            opcode,
            aa,
            tc,
            rd,
            ra,
            rcode,
            questions,
            anwsers,
            auths,
            additional,
        })
    }
}

// # DNSOpCode

primitve_enum_repr! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub enum DNSOpCode {
        type Repr = u8;

        Query = 0,
        IQuery = 1,
        Status = 2,
    };
}

// # DNSReponseCode

primitve_enum_repr! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub enum DNSResponseCode {
        type Repr = u16;

        NoError = 0,
        FormError = 1,
        ServFail = 2,
        NxDomain = 3,
        NotImpl = 4,
        Refused = 5,
        YXDomain = 6,
        YXRRSet = 7,
        NXRRSet = 8,
        NotAuth = 9,
        NotZone = 10,
        DSOTypeNotImplemented = 11,
        BadOPTVersionOrSignature = 16,
        BadKey = 17,
        BadTime = 18,
        BadMode = 19,
        BadName = 20,
        BadAlgo = 21,
        BadTrunc = 22,
        BadCookie = 23,
    };
}

// # DNS Q

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DNSQuestion {
    pub qname: DNSString,
    pub qtyp: DNSType,
    pub qclass: DNSClass,
}

impl IntoBytestreamDepc for DNSQuestion {
    type Error = std::io::Error;
    fn into_bytestream(&self, bytestream: &mut Vec<u8>) -> Result<(), Self::Error> {
        self.qname.into_bytestream(bytestream)?;
        self.qtyp.to_raw().write_to(bytestream, BigEndian)?;
        self.qclass.to_raw().write_to(bytestream, BigEndian)?;

        Ok(())
    }
}

impl FromBytestreamDepc for (DNSQuestion, Vec<u8>) {
    type Error = std::io::Error;
    fn from_bytestream(bytestream: Vec<u8>) -> Result<Self, Self::Error> {
        let (qname, rem) = <(DNSString, Vec<u8>)>::from_bytestream(bytestream)?;

        let mut cursor = Cursor::new(rem);

        let qtyp = DNSType::from_raw(u16::read_from(&mut cursor, BigEndian)?).unwrap();
        let qclass = DNSClass::from_raw(u16::read_from(&mut cursor, BigEndian)?).unwrap();

        let pos = cursor.position() as usize;
        let bytestream = split_off_front(cursor.into_inner(), pos);

        Ok((
            DNSQuestion {
                qname,
                qtyp,
                qclass,
            },
            bytestream,
        ))
    }
}

// # DNS RR

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DNSResourceRecord {
    pub name: DNSString,
    pub typ: DNSType,
    pub class: DNSClass,
    pub ttl: i32,
    // rdata (len = u16)
    pub rdata: Vec<u8>,
}

impl IntoBytestreamDepc for DNSResourceRecord {
    type Error = std::io::Error;
    fn into_bytestream(&self, bytestream: &mut Vec<u8>) -> Result<(), Self::Error> {
        self.name.into_bytestream(bytestream)?;

        self.typ.to_raw().write_to(bytestream, BigEndian)?;
        self.class.to_raw().write_to(bytestream, BigEndian)?;
        self.ttl.write_to(bytestream, BigEndian)?;

        (self.rdata.len() as u16).write_to(bytestream, BigEndian)?;
        for byte in &self.rdata {
            byte.write_to(bytestream, BigEndian)?
        }

        Ok(())
    }
}

impl FromBytestreamDepc for (DNSResourceRecord, Vec<u8>) {
    type Error = std::io::Error;
    fn from_bytestream(bytestream: Vec<u8>) -> Result<Self, Self::Error> {
        // println!("Parsing from {:?}", bytestream);
        let (name, rem) = <(DNSString, Vec<u8>)>::from_bytestream(bytestream)?;
        // println!("{} at {:?}", *name, rem);

        let mut cursor = Cursor::new(rem);

        let typ = DNSType::from_raw(u16::read_from(&mut cursor, BigEndian)?).unwrap();
        let class = DNSClass::from_raw(u16::read_from(&mut cursor, BigEndian)?).unwrap();
        let ttl = i32::read_from(&mut cursor, BigEndian)?;
        let len = u16::read_from(&mut cursor, BigEndian)? as usize;
        let mut rdata = Vec::with_capacity(len);
        for _ in 0..len {
            rdata.push(u8::read_from(&mut cursor, BigEndian)?)
        }

        let pos = cursor.position() as usize;
        let bytestream = split_off_front(cursor.into_inner(), pos);

        Ok((
            DNSResourceRecord {
                name,
                typ,
                class,
                ttl,
                rdata,
            },
            bytestream,
        ))
    }
}

impl DNSResourceRecord {
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
                for i in 0..self.rdata.len() {
                    octets[i] = self.rdata[i];
                }
                format!("{}", Ipv6Addr::from(octets))
            }
            DNSType::NS | DNSType::CNAME | DNSType::PTR => {
                let (dnsstring, _) = <(DNSString, Vec<u8>)>::from_bytestream(self.rdata.clone())
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
            default => write!(f, "{:?}", default),
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

// # DNSString
