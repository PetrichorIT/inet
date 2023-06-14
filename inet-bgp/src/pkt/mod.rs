use crate::types::{AsNumber, BgpIdentifier};
use bytepack::{
    ByteOrder, BytestreamReader, BytestreamWriter, FromBytestream, StreamReader, StreamWriter,
    ToBytestream,
};
use std::{
    fmt::Debug,
    io::{Error, Read, Write},
    net::Ipv4Addr,
};

mod attrs;
mod error;

pub use self::attrs::*;
pub use self::error::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BgpPacket {
    pub marker: u128,
    // pub len: u16,
    // pub typ: BgpPacketType,
    pub kind: BgpPacketKind,
}

impl ToBytestream for BgpPacket {
    type Error = Error;
    fn to_bytestream(&self, bytestream: &mut BytestreamWriter) -> Result<(), Self::Error> {
        bytestream.write_all(&self.marker.to_ne_bytes())?;
        self.kind.to_bytestream(bytestream)
    }
}

impl FromBytestream for BgpPacket {
    type Error = Error;
    fn from_bytestream(bytestream: &mut BytestreamReader) -> Result<Self, Self::Error> {
        let mut marker = [0; 16];
        bytestream.read_exact(&mut marker)?;
        let kind = BgpPacketKind::from_bytestream(bytestream)?;
        Ok(Self {
            marker: u128::from_ne_bytes(marker),
            kind,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BgpPacketKind {
    Open(BgpOpenPacket),
    Update(BgpUpdatePacket),
    Notification(BgpNotificationPacket),
    Keepalive(),
}

impl ToBytestream for BgpPacketKind {
    type Error = Error;
    fn to_bytestream(&self, bytestream: &mut BytestreamWriter) -> Result<(), Self::Error> {
        let len_marker = bytestream.add_marker(0, ByteOrder::BigEndian)?;
        let typ_marker = bytestream.add_marker(0, ByteOrder::BigEndian)?;
        let typ = match self {
            Self::Open(pkt) => {
                pkt.to_bytestream(bytestream)?;
                1u8
            }
            Self::Update(pkt) => {
                pkt.to_bytestream(bytestream)?;
                2u8
            }
            Self::Notification(pkt) => {
                pkt.to_bytestream(bytestream)?;
                3u8
            }
            Self::Keepalive() => 4u8,
        };

        let len = 19 + bytestream.len_since(&typ_marker)?;
        bytestream.write_to_marker(len_marker, len as u16)?;
        bytestream.write_to_marker(typ_marker, typ)
    }
}

impl FromBytestream for BgpPacketKind {
    type Error = Error;
    fn from_bytestream(bytestream: &mut BytestreamReader) -> Result<Self, Self::Error> {
        let _len = u16::read_from(bytestream, ByteOrder::BigEndian)?;
        let typ = u8::read_from(bytestream, ByteOrder::BigEndian)?;

        let kind = match typ {
            1 => BgpPacketKind::Open(BgpOpenPacket::from_bytestream(bytestream)?),
            2 => BgpPacketKind::Update(BgpUpdatePacket::from_bytestream(bytestream)?),
            3 => BgpPacketKind::Notification(BgpNotificationPacket::from_bytestream(bytestream)?),
            4 => BgpPacketKind::Keepalive(),
            _ => todo!(),
        };
        Ok(kind)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BgpOpenPacket {
    pub version: u8,
    /* 3 byte padding */
    pub as_number: AsNumber,
    /* 2 byte padding */
    pub hold_time: u16,
    /* 2 byte padding */
    pub identifier: BgpIdentifier,
    // pub opt_len: u8
    /* 3 byte padding */
    pub options: Vec<BgpOpenOption>,
}

impl ToBytestream for BgpOpenPacket {
    type Error = Error;
    fn to_bytestream(&self, bytestream: &mut BytestreamWriter) -> Result<(), Self::Error> {
        self.version.write_to(bytestream, ByteOrder::BigEndian)?;
        // pad!(bytestream, 3)?;
        self.as_number.write_to(bytestream, ByteOrder::BigEndian)?;
        // pad!(bytestream, 2)?;
        self.hold_time.write_to(bytestream, ByteOrder::BigEndian)?;
        // pad!(bytestream, 2)?;
        self.identifier.write_to(bytestream, ByteOrder::BigEndian)?;
        0u8.write_to(bytestream, ByteOrder::BigEndian)?;
        // pad!(bytestream, 3)?;
        Ok(())
    }
}

impl FromBytestream for BgpOpenPacket {
    type Error = Error;
    fn from_bytestream(bytestream: &mut BytestreamReader) -> Result<Self, Self::Error> {
        let version = u8::read_from(bytestream, ByteOrder::BigEndian)?;
        // rpad!(bytestream, 3)?;
        let as_number = AsNumber::read_from(bytestream, ByteOrder::BigEndian)?;
        // rpad!(bytestream, 2)?;
        let hold_time = u16::read_from(bytestream, ByteOrder::BigEndian)?;
        // rpad!(bytestream, 2)?;
        let identifier = u32::read_from(bytestream, ByteOrder::BigEndian)?;
        // rpad!(bytestream, 4)?;
        Ok(Self {
            version,
            as_number,
            hold_time,
            identifier,
            options: Vec::new(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BgpOpenOption {
    // <type:u8><len:u8><value...>
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BgpUpdatePacket {
    pub withdrawn_routes: Vec<BgpWithdrawnRoute>,
    pub path_attributes: Vec<BgpPathAttribute>,
    pub nlris: Vec<Nlri>,
}

impl ToBytestream for BgpUpdatePacket {
    type Error = Error;
    fn to_bytestream(&self, bytestream: &mut BytestreamWriter) -> Result<(), Self::Error> {
        let wlen_marker = bytestream.add_marker(0, ByteOrder::BigEndian)?;
        for route in &self.withdrawn_routes {
            route.to_bytestream(bytestream)?;
        }
        let wlen = bytestream.len_since(&wlen_marker)?;
        bytestream.write_to_marker(wlen_marker, wlen as u16)?;

        let alen_marker = bytestream.add_marker(0, ByteOrder::BigEndian)?;
        for attr in &self.path_attributes {
            attr.to_bytestream(bytestream)?;
        }
        let alen = bytestream.len_since(&alen_marker)?;
        bytestream.write_to_marker(alen_marker, alen as u16)?;

        for route in &self.nlris {
            route.to_bytestream(bytestream)?;
        }
        Ok(())
    }
}

impl FromBytestream for BgpUpdatePacket {
    type Error = Error;
    fn from_bytestream(bytestream: &mut BytestreamReader) -> Result<Self, Self::Error> {
        // Withdrawn routes
        let wlen = u16::read_from(bytestream, ByteOrder::BigEndian)? as usize;
        let mut wroutes_substream = bytestream.extract(wlen)?;
        let mut withdrawn_routes = Vec::new();
        while !wroutes_substream.is_empty() {
            withdrawn_routes.push(BgpWithdrawnRoute::from_bytestream(&mut wroutes_substream)?)
        }

        // path attributes
        let alen = u16::read_from(bytestream, ByteOrder::BigEndian)? as usize;
        let mut attr_substream = bytestream.extract(alen)?;
        let mut path_attributes = Vec::new();
        while !attr_substream.is_empty() {
            path_attributes.push(BgpPathAttribute::from_bytestream(&mut attr_substream)?)
        }

        // NRLI
        let mut nlris = Vec::new();
        while !bytestream.is_empty() {
            nlris.push(Nlri::from_bytestream(bytestream)?)
        }
        Ok(BgpUpdatePacket {
            withdrawn_routes,
            path_attributes,
            nlris,
        })
    }
}

pub type BgpWithdrawnRoute = Nlri;

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Nlri {
    /* custom encoding */
    bytes: [u8; 4],
}

impl Nlri {
    pub fn prefix(&self) -> Ipv4Addr {
        let dword = u32::from_be_bytes([self.bytes[1], self.bytes[2], self.bytes[3], 0]);
        let mask = !(u32::MAX >> self.bytes[0]);
        Ipv4Addr::from(mask & dword)
    }

    pub fn prefix_len(&self) -> usize {
        self.bytes[0] as usize
    }

    pub fn netmask(&self) -> Ipv4Addr {
        Ipv4Addr::from(!(u32::MAX >> self.prefix_len()))
    }

    pub fn new(prefix: Ipv4Addr, len: u8) -> Self {
        assert!(
            len <= 24,
            "NLRIs are limited to a prefix len between 0 and 24 (inclusive)"
        );
        let oct = prefix.octets();
        let mut ret = Self {
            bytes: [len, oct[0], oct[1], oct[2]],
        };
        ret.normalize();
        ret
    }

    fn normalize(&mut self) {
        let relevant_bytes = 8 + self.bytes[0];
        let mask = !(u32::MAX.checked_shr(relevant_bytes as u32).unwrap_or(0));
        let bytes = u32::from_be_bytes(self.bytes);
        self.bytes = (bytes & mask).to_be_bytes();
    }
}

impl ToBytestream for Nlri {
    type Error = Error;
    fn to_bytestream(&self, bytestream: &mut BytestreamWriter) -> Result<(), Self::Error> {
        let len = self.bytes[0];
        let bit_to_next_octet = (8 - (len % 8)) % 8;
        let octet_len = (len + bit_to_next_octet) / 8;
        bytestream.write_all(&self.bytes[..(octet_len + 1) as usize])
    }
}

impl FromBytestream for Nlri {
    type Error = Error;
    fn from_bytestream(bytestream: &mut BytestreamReader) -> Result<Self, Self::Error> {
        let prefix_len = u8::read_from(bytestream, ByteOrder::BigEndian)?;
        assert!(prefix_len <= 24, "invalid prefix len");

        let bit_to_next_octet = (8 - (prefix_len % 8)) % 8;
        let octet_len = (prefix_len + bit_to_next_octet) / 8;
        let mut bytes = [0; 4];
        bytes[0] = prefix_len;
        bytestream.read_exact(&mut bytes[1..(octet_len + 1) as usize])?;
        Ok(Self { bytes })
    }
}

impl Debug for Nlri {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.prefix(), self.prefix_len())
    }
}
#[cfg(test)]
mod tests {
    use std::io;

    use super::*;

    #[test]
    fn parse_nlri() -> io::Result<()> {
        let nlri = Nlri::new(Ipv4Addr::new(255, 254, 253, 252), 16);
        assert_eq!(nlri, Nlri::from_buffer(nlri.to_buffer()?)?);

        let nlri = Nlri::new(Ipv4Addr::new(255, 254, 253, 252), 17);
        assert_eq!(nlri, Nlri::from_buffer(nlri.to_buffer()?)?);

        let nlri = Nlri::new(Ipv4Addr::new(255, 254, 253, 252), 18);
        assert_eq!(nlri, Nlri::from_buffer(nlri.to_buffer()?)?);

        let nlri = Nlri::new(Ipv4Addr::new(255, 254, 253, 252), 19);
        assert_eq!(nlri, Nlri::from_buffer(nlri.to_buffer()?)?);

        let nlri = Nlri::new(Ipv4Addr::new(255, 254, 253, 252), 21);
        assert_eq!(nlri, Nlri::from_buffer(nlri.to_buffer()?)?);

        Ok(())
    }
}
