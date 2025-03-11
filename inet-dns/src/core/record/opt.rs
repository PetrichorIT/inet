use std::io::{self, Read, Write};

use bytes::Buf;
use bytes_io::{BytesReader, BytesWriter, FromBytes, ReadBytesExt, ToBytes, WriteBytesExt, BE};

use crate::core::DnsString;

use super::{RawResourceRecord, ResourceRecord, ResourceRecordClass, ResourceRecordTyp};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OptResourceRecord {
    pub name: DnsString,
    pub udp_payload_size: u16,
    pub rcode: u8,
    pub version: bool,
    pub options: Vec<Opt>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Opt {
    pub code: u16,
    pub value: Vec<u8>,
}

// Do NOT implement `TryFrom<ZonefileLineRecord` since OPT RR's should never
// appear in zonefiles, but rather only in resolver queries.

impl TryFrom<RawResourceRecord> for OptResourceRecord {
    type Error = io::Error;
    fn try_from(value: RawResourceRecord) -> Result<Self, Self::Error> {
        if !value.name.labels().is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "OPT RR's should not have a name",
            ));
        }

        let udp_payload_size = value.class.to_raw_repr();
        let rcode = ((value.ttl & 0xff_00_00_00) >> 24) as u8;
        let version = (value.ttl & 0x00_ff_00_00) >> 16 != 0;

        let mut options = Vec::new();
        let mut slice = &value.rdata[..];
        while slice.has_remaining() {
            let opt = Opt::read_from(&mut slice)?;
            options.push(opt);
        }

        Ok(OptResourceRecord {
            name: value.name,
            udp_payload_size,
            rcode,
            version,
            options,
        })
    }
}

impl ResourceRecord for OptResourceRecord {
    fn name(&self) -> &DnsString {
        &self.name
    }
    fn typ(&self) -> super::ResourceRecordTyp {
        ResourceRecordTyp::OPT
    }
    fn class(&self) -> Option<ResourceRecordClass> {
        Some(ResourceRecordClass::from_raw_repr(self.udp_payload_size).unwrap())
    }
    fn ttl(&self) -> Option<u32> {
        let mut ttl = 0u32;
        ttl |= (self.rcode as u32) << 24;
        ttl |= (self.version as u32) << 16;
        Some(ttl)
    }
    fn rdata(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        for opt in &self.options {
            opt.write_to(&mut buf).expect("cannot fail");
        }
        buf
    }
    fn rdata_fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.options)
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

impl FromBytes for Opt {
    type Error = io::Error;
    fn from_bytes(stream: &mut BytesReader) -> Result<Self, Self::Error> {
        let code = stream.read_u16::<BE>()?;
        let len = stream.read_u16::<BE>()?;
        let mut value = vec![0; len as usize];
        stream.read_exact(&mut value)?;
        Ok(Opt { code, value })
    }
}

impl ToBytes for Opt {
    type Error = io::Error;
    fn to_bytes(&self, stream: &mut BytesWriter) -> Result<(), Self::Error> {
        stream.write_u16::<BE>(self.code)?;
        stream.write_u16::<BE>(self.value.len() as u16)?;
        stream.write_all(&self.value)
    }
}
