use crate::types::{AsNumber, BgpIdentifier};
use bytes_io::{BE, BytesReader, BytesWriter, FromBytes, ReadBytesExt, ToBytes, WriteBytesExt};
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BgpPacket {
    pub marker: u128,
    // pub len: u16,
    // pub typ: BgpPacketType,
    pub kind: BgpPacketKind,
}

impl ToBytes for BgpPacket {
    type Error = Error;
    fn to_bytes(&self, bytestream: &mut BytesWriter) -> Result<(), Self::Error> {
        bytestream.write_all(&self.marker.to_ne_bytes())?;
        let len_marker = bytestream.marker::<u16>();
        self.kind.to_bytes(bytestream)?;
        let len = 20 + bytestream.bytes_written_since(&len_marker) as u16;
        bytestream.apply(len_marker).write_u16::<BE>(len)?;
        Ok(())
    }
}

impl FromBytes for BgpPacket {
    type Error = Error;
    fn from_bytes(bytestream: &mut BytesReader) -> Result<Self, Self::Error> {
        let mut marker = [0; 16];
        bytestream.read_exact(&mut marker)?;
        let len = bytestream.read_u16::<BE>()?;
        let kind = bytestream.extract((len - 20) as usize, BgpPacketKind::from_bytes)?;
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

impl ToBytes for BgpPacketKind {
    type Error = Error;
    fn to_bytes(&self, bytestream: &mut BytesWriter) -> Result<(), Self::Error> {
        let typ_marker = bytestream.marker::<u8>();
        let typ = match self {
            Self::Open(pkt) => {
                pkt.to_bytes(bytestream)?;
                1u8
            }
            Self::Update(pkt) => {
                pkt.to_bytes(bytestream)?;
                2u8
            }
            Self::Notification(pkt) => {
                pkt.to_bytes(bytestream)?;
                3u8
            }
            Self::Keepalive() => 4u8,
        };
        bytestream.apply(typ_marker).write_u8(typ)
    }
}

impl FromBytes for BgpPacketKind {
    type Error = Error;
    fn from_bytes(bytestream: &mut BytesReader) -> Result<Self, Self::Error> {
        let typ = bytestream.read_u8()?;
        let kind = match typ {
            1 => BgpPacketKind::Open(BgpOpenPacket::from_bytes(bytestream)?),
            2 => BgpPacketKind::Update(BgpUpdatePacket::from_bytes(bytestream)?),
            3 => BgpPacketKind::Notification(BgpNotificationPacket::from_bytes(bytestream)?),
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

impl ToBytes for BgpOpenPacket {
    type Error = Error;
    fn to_bytes(&self, bytestream: &mut BytesWriter) -> Result<(), Self::Error> {
        bytestream.write_u8(self.version)?;
        bytestream.write_u16::<BE>(self.as_number)?;
        bytestream.write_u16::<BE>(self.hold_time)?;
        bytestream.write_u32::<BE>(self.identifier)?;
        bytestream.write_u8(0)?;
        Ok(())
    }
}

impl FromBytes for BgpOpenPacket {
    type Error = Error;
    fn from_bytes(bytestream: &mut BytesReader) -> Result<Self, Self::Error> {
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

impl ToBytes for BgpUpdatePacket {
    type Error = Error;
    fn to_bytes(&self, bytestream: &mut BytesWriter) -> Result<(), Self::Error> {
        let wlen_marker = bytestream.marker::<u16>();
        for route in &self.withdrawn_routes {
            route.to_bytes(bytestream)?;
        }
        let wlen = bytestream.bytes_written_since(&wlen_marker);
        bytestream.apply(wlen_marker).write_u16::<BE>(wlen as u16)?;

        let alen_marker = bytestream.marker::<u16>();
        for attr in &self.path_attributes {
            attr.to_bytes(bytestream)?;
        }
        let alen = bytestream.bytes_written_since(&alen_marker);
        bytestream.apply(alen_marker).write_u16::<BE>(alen as u16)?;

        for route in &self.nlris {
            route.to_bytes(bytestream)?;
        }
        Ok(())
    }
}

impl FromBytes for BgpUpdatePacket {
    type Error = Error;
    fn from_bytes(bytestream: &mut BytesReader) -> Result<Self, Self::Error> {
        // Withdrawn routes
        let wlen = bytestream.read_u16::<BE>()? as usize;
        let withdrawn_routes = bytestream.extract(wlen, |body| {
            let mut withdrawn_routes = Vec::new();
            while body.has_remaining() {
                withdrawn_routes.push(BgpWithdrawnRoute::from_bytes(body)?);
            }
            Ok(withdrawn_routes)
        })?;

        // path attributes
        let alen = bytestream.read_u16::<BE>()? as usize;
        let path_attributes = bytestream.extract(alen, |body| {
            let mut path_attributes = Vec::new();
            while body.has_remaining() {
                path_attributes.push(BgpPathAttribute::from_bytes(body)?);
            }
            Ok(path_attributes)
        })?;

        // NRLI
        let mut nlris = Vec::new();
        while bytestream.has_remaining() {
            nlris.push(Nlri::from_bytes(bytestream)?);
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
    #[must_use]
    pub fn prefix(&self) -> Ipv4Addr {
        let dword = u32::from_be_bytes([self.bytes[1], self.bytes[2], self.bytes[3], 0]);
        let mask = !(u32::MAX >> self.bytes[0]);
        Ipv4Addr::from(mask & dword)
    }

    #[must_use]
    pub fn prefix_len(&self) -> usize {
        self.bytes[0] as usize
    }

    #[must_use]
    pub fn netmask(&self) -> Ipv4Addr {
        Ipv4Addr::from(!(u32::MAX >> self.prefix_len()))
    }

    /// # Panics
    ///
    /// Panics if len <= 24
    #[must_use]
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
        let mask = !(u32::MAX.checked_shr(u32::from(relevant_bytes)).unwrap_or(0));
        let bytes = u32::from_be_bytes(self.bytes);
        self.bytes = (bytes & mask).to_be_bytes();
    }
}

impl ToBytes for Nlri {
    type Error = Error;
    fn to_bytes(&self, bytestream: &mut BytesWriter) -> Result<(), Self::Error> {
        let len = self.bytes[0];
        let bit_to_next_octet = (8 - (len % 8)) % 8;
        let octet_len = (len + bit_to_next_octet) / 8;
        bytestream.write_all(&self.bytes[..(octet_len + 1) as usize])
    }
}

impl FromBytes for Nlri {
    type Error = Error;
    fn from_bytes(bytestream: &mut BytesReader) -> Result<Self, Self::Error> {
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

    use bytes_io::assert_encoding_e2e;

    use super::*;

    #[test]
    fn parse_nlri() -> io::Result<()> {
        let nlri = Nlri::new(Ipv4Addr::new(255, 254, 253, 252), 16);
        assert_eq!(nlri, Nlri::peek_from(&nlri.write_to_vec()?[..])?);

        let nlri = Nlri::new(Ipv4Addr::new(255, 254, 253, 252), 17);
        assert_eq!(nlri, Nlri::peek_from(&nlri.write_to_vec()?[..])?);

        let nlri = Nlri::new(Ipv4Addr::new(255, 254, 253, 252), 18);
        assert_eq!(nlri, Nlri::peek_from(&nlri.write_to_vec()?[..])?);

        let nlri = Nlri::new(Ipv4Addr::new(255, 254, 253, 252), 19);
        assert_eq!(nlri, Nlri::peek_from(&nlri.write_to_vec()?[..])?);

        let nlri = Nlri::new(Ipv4Addr::new(255, 254, 253, 252), 21);
        assert_eq!(nlri, Nlri::peek_from(&nlri.write_to_vec()?[..])?);

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

        assert_eq!(
            open,
            BgpPacket::peek_from(&open.write_to_vec()?[..]).unwrap()
        );
        Ok(())
    }

    #[test]
    fn e2e_encoding_packet() {
        assert_encoding_e2e(&[
            BgpPacket {
                marker: 312312,
                kind: BgpPacketKind::Open(BgpOpenPacket {
                    version: 4,
                    as_number: 2000,
                    hold_time: 100,
                    identifier: 10001,
                    options: Vec::new(),
                }),
            },
            BgpPacket {
                marker: 312312,
                kind: BgpPacketKind::Update(BgpUpdatePacket {
                    withdrawn_routes: vec![],
                    path_attributes: vec![],
                    nlris: vec![],
                }),
            },
        ]);
    }

    #[test]
    fn e2e_encoding_open_packet() {
        assert_encoding_e2e(&[
            BgpOpenPacket {
                version: 144,
                as_number: 3123,
                hold_time: 180,
                identifier: 10001,
                options: vec![],
            },
            BgpOpenPacket {
                version: 1,
                as_number: 3123,
                hold_time: 0100,
                identifier: 3123,
                options: vec![],
            },
        ]);
    }

    #[test]
    fn e2e_encoding_update_packet() {
        assert_encoding_e2e(&[
            BgpUpdatePacket {
                withdrawn_routes: vec![Nlri::new(Ipv4Addr::new(255, 254, 253, 252), 16)],
                path_attributes: vec![BgpPathAttribute {
                    flags: BgpPathAttributeFlags::default(),
                    attr: BgpPathAttributeKind::Origin(BgpPathAttributeOrigin::Igp),
                }],
                nlris: vec![Nlri::new(Ipv4Addr::new(255, 254, 253, 252), 21)],
            },
            BgpUpdatePacket {
                withdrawn_routes: vec![],
                path_attributes: vec![BgpPathAttribute {
                    flags: BgpPathAttributeFlags::default(),
                    attr: BgpPathAttributeKind::NextHop(BgpPathAttributeNextHop {
                        hop: Ipv4Addr::new(3, 74, 4, 9),
                    }),
                }],
                nlris: vec![Nlri::new(Ipv4Addr::new(255, 254, 253, 252), 21)],
            },
        ]);
    }

    #[test]
    fn e2e_encoding_nlri() {
        assert_encoding_e2e(&[
            Nlri::new(Ipv4Addr::new(255, 254, 253, 252), 16),
            Nlri::new(Ipv4Addr::new(255, 254, 253, 252), 17),
            Nlri::new(Ipv4Addr::new(255, 254, 253, 252), 18),
            Nlri::new(Ipv4Addr::new(255, 254, 253, 252), 19),
            Nlri::new(Ipv4Addr::new(255, 254, 253, 252), 21),
        ]);
    }
}
