use std::io;

use crate::core::{types::DnsString, ZonefileLineRecord};

use super::{ResourceRecord, ResourceRecordClass, ResourceRecordTyp};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawResourceRecord {
    pub name: DnsString,
    pub ttl: u32,
    pub typ: ResourceRecordTyp,
    pub class: ResourceRecordClass,
    pub rdata: Vec<u8>,
}

impl TryFrom<ZonefileLineRecord> for RawResourceRecord {
    type Error = io::Error;
    fn try_from(raw: ZonefileLineRecord) -> Result<Self, Self::Error> {
        Ok(Self {
            name: raw.name.clone(),
            ttl: raw.ttl as u32,
            typ: raw.typ,
            class: raw.class,
            rdata: raw.rdata.as_bytes().to_vec(),
        })
    }
}

impl ResourceRecord for RawResourceRecord {
    fn name(&self) -> &DnsString {
        &self.name
    }
    fn ttl(&self) -> Option<u32> {
        Some(self.ttl)
    }
    fn typ(&self) -> ResourceRecordTyp {
        self.typ
    }
    fn class(&self) -> Option<ResourceRecordClass> {
        Some(self.class)
    }
    fn rdata(&self) -> Vec<u8> {
        self.rdata.clone()
    }
    fn rdata_fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "r#\"{}\"#", String::from_utf8_lossy(&self.rdata))
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}
