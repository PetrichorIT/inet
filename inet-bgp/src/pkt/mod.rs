use crate::types::{AsNumber, BgpIdentifier};
use bytepack::{
    BytestreamReader, BytestreamWriter, FromBytestream, ReadBytesExt, ToBytestream, WriteBytesExt,
    BE,
};
use des::{prelude::current, time::SimTime};
use std::{
    fmt::Debug,
    io::{Error, Read, Write},
    net::Ipv4Addr,
    str::FromStr,
};

mod attrs;
mod error;

pub use self::attrs::*;
pub use self::error::*;

#[derive(Debug)]
pub enum BgpParsingError {
    Error(Error),
    Incomplete,
}

impl From<Error> for BgpParsingError {
    fn from(value: Error) -> Self {
        Self::Error(value)
    }
}

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
        let len_marker = bytestream.create_typed_marker::<u16>()?;
        self.kind.to_bytestream(bytestream)?;
        let len = 20 + bytestream.len_since_marker(&len_marker) as u16;
        bytestream.update_marker(&len_marker).write_u16::<BE>(len)?;
        Ok(())
    }
}

impl FromBytestream for BgpPacket {
    type Error = BgpParsingError;
    fn from_bytestream(bytestream: &mut BytestreamReader) -> Result<Self, Self::Error> {
        let mut marker = [0; 16];
        bytestream.read_exact(&mut marker)?;
        let len = bytestream.read_u16::<BE>()?;
        let mut substream = bytestream.extract((len - 20) as usize)?;
        let kind = BgpPacketKind::from_bytestream(&mut substream)?;
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
        let typ_marker = bytestream.create_typed_marker::<u8>()?;
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
        bytestream.update_marker(&typ_marker).write_u8(typ)
    }
}

impl FromBytestream for BgpPacketKind {
    type Error = Error;
    fn from_bytestream(bytestream: &mut BytestreamReader) -> Result<Self, Self::Error> {
        let typ = bytestream.read_u8()?;
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
        bytestream.write_u8(self.version)?;
        bytestream.write_u16::<BE>(self.as_number)?;
        bytestream.write_u16::<BE>(self.hold_time)?;
        bytestream.write_u32::<BE>(self.identifier)?;
        bytestream.write_u8(0)?;
        Ok(())
    }
}

impl FromBytestream for BgpOpenPacket {
    type Error = Error;
    fn from_bytestream(bytestream: &mut BytestreamReader) -> Result<Self, Self::Error> {
        let version = bytestream.read_u8()?;
        let as_number = bytestream.read_u16::<BE>()?;
        let hold_time = bytestream.read_u16::<BE>()?;
        let identifier = bytestream.read_u32::<BE>()?;
        assert_eq!(0, bytestream.read_u8()?); // SURE ?
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
        let wlen_marker = bytestream.create_typed_marker::<u16>()?;
        for route in &self.withdrawn_routes {
            route.to_bytestream(bytestream)?;
        }
        let wlen = bytestream.len_since_marker(&wlen_marker);
        bytestream
            .update_marker(&wlen_marker)
            .write_u16::<BE>(wlen as u16)?;

        let alen_marker = bytestream.create_typed_marker::<u16>()?;
        for attr in &self.path_attributes {
            attr.to_bytestream(bytestream)?;
        }
        let alen = bytestream.len_since_marker(&alen_marker);
        bytestream
            .update_marker(&alen_marker)
            .write_u16::<BE>(alen as u16)?;

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
        let wlen = bytestream.read_u16::<BE>()? as usize;
        let mut wroutes_substream = bytestream.extract(wlen)?;
        let mut withdrawn_routes = Vec::new();
        while !wroutes_substream.is_empty() {
            withdrawn_routes.push(BgpWithdrawnRoute::from_bytestream(&mut wroutes_substream)?)
        }

        // path attributes
        let alen = bytestream.read_u16::<BE>()? as usize;
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
        let prefix_len = bytestream.read_u8()?;
        assert!(
            prefix_len <= 24,
            "[ {} ] {} invalid prefix len\n{:?}",
            current().path(),
            SimTime::now(),
            bytestream
        );

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

impl FromStr for Nlri {
    type Err = Box<dyn std::error::Error>;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (lhs, rhs) = s.split_once('/').ok_or("missing delimiter '/'")?;
        Ok(Nlri::new(lhs.parse()?, rhs.parse()?))
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::io;

    use super::*;

    #[test]
    fn parse_nlri() -> io::Result<()> {
        let nlri = Nlri::new(Ipv4Addr::new(255, 254, 253, 252), 16);
        assert_eq!(nlri, Nlri::from_slice(&nlri.to_vec()?)?);

        let nlri = Nlri::new(Ipv4Addr::new(255, 254, 253, 252), 17);
        assert_eq!(nlri, Nlri::from_slice(&nlri.to_vec()?)?);

        let nlri = Nlri::new(Ipv4Addr::new(255, 254, 253, 252), 18);
        assert_eq!(nlri, Nlri::from_slice(&nlri.to_vec()?)?);

        let nlri = Nlri::new(Ipv4Addr::new(255, 254, 253, 252), 19);
        assert_eq!(nlri, Nlri::from_slice(&nlri.to_vec()?)?);

        let nlri = Nlri::new(Ipv4Addr::new(255, 254, 253, 252), 21);
        assert_eq!(nlri, Nlri::from_slice(&nlri.to_vec()?)?);

        Ok(())
    }

    #[test]
    fn parse_open_pkt() -> Result<(), Box<dyn Error>> {
        let open = BgpPacket {
            marker: u128::MAX,
            kind: BgpPacketKind::Open(BgpOpenPacket {
                version: 4,
                as_number: 2000,
                hold_time: 100,
                identifier: 10001,
                options: Vec::new(),
            }),
        };

        assert_eq!(open, BgpPacket::from_slice(&open.to_vec()?).unwrap());
        Ok(())
    }
}
