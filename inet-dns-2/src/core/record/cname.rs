use std::io;

use super::{RawResourceRecord, ResourceRecord, ResourceRecordClass};
use crate::core::{DnsString, ZonefileLineRecord};
use bytepack::{FromBytestream, ToBytestream};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CNameResourceRecord {
    pub name: DnsString,
    pub ttl: u32,
    pub class: ResourceRecordClass,
    pub target: DnsString,
}

impl TryFrom<ZonefileLineRecord> for CNameResourceRecord {
    type Error = io::Error;
    fn try_from(raw: ZonefileLineRecord) -> Result<Self, Self::Error> {
        Ok(Self {
            name: raw.name.clone(),
            ttl: raw.ttl,
            class: raw.class,
            target: DnsString::from_zonefile_definition(&raw.rdata, &raw.origin),
        })
    }
}

impl TryFrom<RawResourceRecord> for CNameResourceRecord {
    type Error = io::Error;
    fn try_from(raw: RawResourceRecord) -> Result<Self, Self::Error> {
        Ok(Self {
            name: raw.name,
            ttl: raw.ttl,
            class: raw.class,
            target: DnsString::from_slice(&raw.rdata)?,
        })
    }
}

impl ResourceRecord for CNameResourceRecord {
    fn name(&self) -> &DnsString {
        &self.name
    }
    fn ttl(&self) -> Option<u32> {
        Some(self.ttl)
    }
    fn typ(&self) -> super::ResourceRecordTyp {
        super::ResourceRecordTyp::CNAME
    }
    fn class(&self) -> Option<ResourceRecordClass> {
        Some(self.class)
    }
    fn rdata(&self) -> Vec<u8> {
        self.target.to_vec().expect("invalid parsing failure")
    }
    fn rdata_fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.target)
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}
