use super::{RawResourceRecord, ResourceRecord, ResourceRecordClass, ResourceRecordTyp};
use crate::core::{types::DnsString, ZonefileLineRecord};
use std::{
    io,
    net::{Ipv4Addr, Ipv6Addr},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AResourceRecord {
    name: DnsString,
    ttl: u32,
    class: ResourceRecordClass,
    addr: Ipv4Addr,
}

impl TryFrom<ZonefileLineRecord> for AResourceRecord {
    type Error = io::Error;
    fn try_from(raw: ZonefileLineRecord) -> Result<Self, Self::Error> {
        Ok(Self {
            name: raw.name.clone(),
            ttl: raw.ttl as u32,
            class: raw.class,
            addr: raw.rdata.parse().map_err(io::Error::other)?,
        })
    }
}

impl TryFrom<RawResourceRecord> for AResourceRecord {
    type Error = io::Error;
    fn try_from(raw: RawResourceRecord) -> Result<Self, Self::Error> {
        if raw.rdata.len() != 4 {
            dbg!(raw);
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "expected rdata with 4 bytes to form an A record",
            ));
        }
        let mut bytes = [0u8; 4];
        bytes[..4].copy_from_slice(&raw.rdata[..4]);
        Ok(Self {
            name: raw.name,
            ttl: raw.ttl,
            class: raw.class,
            addr: Ipv4Addr::from(bytes),
        })
    }
}

impl ResourceRecord for AResourceRecord {
    fn name(&self) -> &DnsString {
        &self.name
    }
    fn ttl(&self) -> Option<u32> {
        Some(self.ttl)
    }
    fn typ(&self) -> ResourceRecordTyp {
        ResourceRecordTyp::A
    }
    fn class(&self) -> Option<ResourceRecordClass> {
        Some(self.class)
    }
    fn rdata(&self) -> Vec<u8> {
        self.addr.octets().to_vec()
    }
    fn rdata_fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.addr)
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AAAAResourceRecord {
    name: DnsString,
    ttl: u32,
    class: ResourceRecordClass,
    addr: Ipv6Addr,
}

impl TryFrom<ZonefileLineRecord> for AAAAResourceRecord {
    type Error = io::Error;
    fn try_from(raw: ZonefileLineRecord) -> Result<Self, Self::Error> {
        Ok(Self {
            name: raw.name.clone(),
            ttl: raw.ttl as u32,
            class: raw.class,
            addr: raw.rdata.parse().map_err(io::Error::other)?,
        })
    }
}

impl TryFrom<RawResourceRecord> for AAAAResourceRecord {
    type Error = io::Error;
    fn try_from(raw: RawResourceRecord) -> Result<Self, Self::Error> {
        if raw.rdata.len() != 16 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "expected rdata with 16 bytes to form an A record",
            ));
        }
        let mut bytes = [0u8; 16];
        bytes[..16].copy_from_slice(&raw.rdata[..16]);
        Ok(Self {
            name: raw.name,
            ttl: raw.ttl,
            class: raw.class,
            addr: Ipv6Addr::from(bytes),
        })
    }
}

impl ResourceRecord for AAAAResourceRecord {
    fn name(&self) -> &DnsString {
        &self.name
    }
    fn ttl(&self) -> Option<u32> {
        Some(self.ttl)
    }
    fn typ(&self) -> ResourceRecordTyp {
        ResourceRecordTyp::AAAA
    }
    fn class(&self) -> Option<ResourceRecordClass> {
        Some(self.class)
    }
    fn rdata(&self) -> Vec<u8> {
        self.addr.octets().to_vec()
    }
    fn rdata_fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.addr)
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}
