use std::io;

use bytes::BufMut;
use bytes_io::{BE, FromBytes, ReadBytesExt, ToBytes};

use crate::core::{ZonefileLineRecord, string::DnsString};

use super::{RawResourceRecord, ResourceRecord, ResourceRecordClass};

/// A resource record representing the start of a zone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SoaResourceRecord {
    pub name: DnsString,
    pub class: ResourceRecordClass,
    pub ttl: u32,
    pub mname: DnsString,
    pub rname: DnsString,
    pub serial: u32,
    pub refresh: u32,
    pub retry: u32,
    pub expire: u32,
    pub minimum: u32,
}

impl TryFrom<ZonefileLineRecord> for SoaResourceRecord {
    type Error = io::Error;
    fn try_from(raw: ZonefileLineRecord) -> Result<Self, Self::Error> {
        let splits = raw.rdata.splitn(3, ' ').collect::<Vec<_>>();
        assert_eq!(splits.len(), 3);

        let numbers: Vec<u32> = splits[2]
            .trim_matches('(')
            .trim_matches(')')
            .split_whitespace()
            .map(str::parse::<u32>)
            .collect::<Result<_, _>>()
            .map_err(io::Error::other)?;
        assert_eq!(numbers.len(), 5);

        Ok(Self {
            name: raw.name.clone(),
            ttl: raw.ttl,
            class: raw.class,
            mname: DnsString::from_zonefile(splits[0], &raw.origin)?,
            rname: DnsString::from_zonefile(splits[1], &raw.origin)?,
            serial: numbers[0],
            refresh: numbers[1],
            retry: numbers[2],
            expire: numbers[3],
            minimum: numbers[4],
        })
    }
}

impl TryFrom<RawResourceRecord> for SoaResourceRecord {
    type Error = io::Error;
    fn try_from(raw: RawResourceRecord) -> Result<Self, Self::Error> {
        let mut slice = &raw.rdata[..];

        Ok(Self {
            name: raw.name,
            ttl: raw.ttl,
            class: raw.class,
            mname: DnsString::read_from(&mut slice)?,
            rname: DnsString::read_from(&mut slice)?,
            serial: slice.read_u32::<BE>()?,
            refresh: slice.read_u32::<BE>()?,
            retry: slice.read_u32::<BE>()?,
            expire: slice.read_u32::<BE>()?,
            minimum: slice.read_u32::<BE>()?,
        })
    }
}

impl ResourceRecord for SoaResourceRecord {
    fn name(&self) -> &DnsString {
        &self.name
    }
    fn ttl(&self) -> Option<u32> {
        Some(self.ttl)
    }
    fn typ(&self) -> super::ResourceRecordTyp {
        super::ResourceRecordTyp::SOA
    }
    fn class(&self) -> Option<ResourceRecordClass> {
        Some(self.class)
    }
    fn rdata(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.mname
            .write_to(&mut buf)
            .expect("illegal parsing error");
        self.rname
            .write_to(&mut buf)
            .expect("illegal parsing error");
        buf.put_u32(self.serial);
        buf.put_u32(self.refresh);
        buf.put_u32(self.retry);
        buf.put_u32(self.expire);
        buf.put_u32(self.minimum);

        buf
    }
    fn rdata_fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} {} ({} {} {} {} {})",
            self.mname,
            self.rname,
            self.serial,
            self.refresh,
            self.retry,
            self.expire,
            self.minimum
        )
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}
