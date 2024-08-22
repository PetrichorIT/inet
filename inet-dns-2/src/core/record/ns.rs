use super::{RawResourceRecord, ResourceRecord, ResourceRecordClass};
use crate::core::{types::DnsString, ZonefileLineRecord};
use bytepack::{FromBytestream, ToBytestream};
use std::io;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NsResourceRecord {
    pub domain: DnsString,
    pub ttl: u32,
    pub class: ResourceRecordClass,
    pub nameserver: DnsString,
}

impl TryFrom<ZonefileLineRecord> for NsResourceRecord {
    type Error = io::Error;
    fn try_from(raw: ZonefileLineRecord) -> Result<Self, Self::Error> {
        Ok(Self {
            domain: raw.name.clone(),
            ttl: raw.ttl as u32,
            class: raw.class,
            nameserver: DnsString::from_zonefile(&raw.rdata, &raw.origin)?,
        })
    }
}

impl TryFrom<RawResourceRecord> for NsResourceRecord {
    type Error = io::Error;
    fn try_from(raw: RawResourceRecord) -> Result<Self, Self::Error> {
        Ok(Self {
            domain: raw.name,
            ttl: raw.ttl,
            class: raw.class,
            nameserver: DnsString::from_slice(&raw.rdata)?,
        })
    }
}

impl ResourceRecord for NsResourceRecord {
    fn name(&self) -> &DnsString {
        &self.domain
    }
    fn ttl(&self) -> Option<u32> {
        Some(self.ttl)
    }
    fn typ(&self) -> super::ResourceRecordTyp {
        super::ResourceRecordTyp::NS
    }
    fn class(&self) -> Option<ResourceRecordClass> {
        Some(self.class)
    }
    fn rdata(&self) -> Vec<u8> {
        self.nameserver.to_vec().expect("invalid parsing failure")
    }
    fn rdata_fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.nameserver)
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}
