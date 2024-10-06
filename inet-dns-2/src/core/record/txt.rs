use super::{RawResourceRecord, ResourceRecord, ResourceRecordClass};
use crate::core::{DnsString, ZonefileLineRecord};
use std::io;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxtResourceRecord {
    pub name: DnsString,
    pub ttl: u32,
    pub class: ResourceRecordClass,
    pub text: String,
}

impl TryFrom<ZonefileLineRecord> for TxtResourceRecord {
    type Error = io::Error;
    fn try_from(raw: ZonefileLineRecord) -> Result<Self, Self::Error> {
        Ok(TxtResourceRecord {
            name: raw.name,
            ttl: raw.ttl,
            class: raw.class,
            text: raw.rdata.clone(),
        })
    }
}

impl TryFrom<RawResourceRecord> for TxtResourceRecord {
    type Error = io::Error;
    fn try_from(raw: RawResourceRecord) -> Result<Self, Self::Error> {
        Ok(TxtResourceRecord {
            name: raw.name,
            ttl: raw.ttl,
            class: raw.class,
            text: String::from_utf8_lossy(&raw.rdata).to_string(),
        })
    }
}

impl ResourceRecord for TxtResourceRecord {
    fn name(&self) -> &DnsString {
        &self.name
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
        self.text.as_bytes().to_vec()
    }
    fn rdata_fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.text)
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}
