use std::io;

use bytepack::{FromBytestream, ToBytestream};

use crate::core::{types::DnsString, ZonefileLineRecord};

use super::{RawResourceRecord, ResourceRecord, ResourceRecordClass};

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
        let splits = raw.rdata.splitn(3, " ").collect::<Vec<_>>();
        assert_eq!(splits.len(), 3);

        let numbers: Vec<u32> = splits[2]
            .trim_matches('(')
            .trim_matches(')')
            .split_whitespace()
            .map(|s| s.parse::<u32>())
            .collect::<Result<_, _>>()
            .map_err(io::Error::other)?;
        assert_eq!(numbers.len(), 5);

        Ok(Self {
            name: raw.name.clone(),
            ttl: raw.ttl as u32,
            class: raw.class,
            mname: DnsString::from_zonefile(&splits[0], &raw.origin)?,
            rname: DnsString::from_zonefile(&splits[1], &raw.origin)?,
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
            mname: DnsString::read_from_slice(&mut slice)?,
            rname: DnsString::read_from_slice(&mut slice)?,
            serial: u32::read_from_slice(&mut slice)?,
            refresh: u32::read_from_slice(&mut slice)?,
            retry: u32::read_from_slice(&mut slice)?,
            expire: u32::read_from_slice(&mut slice)?,
            minimum: u32::read_from_slice(&mut slice)?,
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
        self.mname.append_to_vec(&mut buf).unwrap();
        self.rname.append_to_vec(&mut buf).unwrap();
        self.serial.append_to_vec(&mut buf).unwrap();
        self.refresh.append_to_vec(&mut buf).unwrap();
        self.retry.append_to_vec(&mut buf).unwrap();
        self.expire.append_to_vec(&mut buf).unwrap();
        self.minimum.append_to_vec(&mut buf).unwrap();

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
