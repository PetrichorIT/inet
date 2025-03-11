use super::{RawResourceRecord, ResourceRecord, ResourceRecordClass};
use crate::core::{DnsString, ZonefileLineRecord};
use bytes_io::{FromBytes, ToBytes};
use std::io;

/// A resource record used for inverse name resolution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PtrResourceRecord {
    pub addr: DnsString,
    pub ttl: u32,
    pub class: ResourceRecordClass,
    pub name: DnsString,
}

impl TryFrom<ZonefileLineRecord> for PtrResourceRecord {
    type Error = io::Error;
    fn try_from(raw: ZonefileLineRecord) -> Result<Self, Self::Error> {
        Ok(PtrResourceRecord {
            addr: raw.name,
            ttl: raw.ttl,
            class: raw.class,
            name: DnsString::from_zonefile(&raw.rdata, &raw.origin)?,
        })
    }
}

impl TryFrom<RawResourceRecord> for PtrResourceRecord {
    type Error = io::Error;
    fn try_from(raw: RawResourceRecord) -> Result<Self, Self::Error> {
        Ok(PtrResourceRecord {
            addr: raw.name,
            ttl: raw.ttl,
            class: raw.class,
            name: DnsString::peek_from(&raw.rdata[..])?,
        })
    }
}

impl ResourceRecord for PtrResourceRecord {
    #[allow(clippy::misnamed_getters)]
    fn name(&self) -> &DnsString {
        &self.addr
    }
    fn ttl(&self) -> Option<u32> {
        Some(self.ttl)
    }
    fn typ(&self) -> super::ResourceRecordTyp {
        super::ResourceRecordTyp::PTR
    }
    fn class(&self) -> Option<ResourceRecordClass> {
        Some(self.class)
    }
    fn rdata(&self) -> Vec<u8> {
        self.name.write_to_vec().expect("invalid parsing failure")
    }
    fn rdata_fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name)
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}
