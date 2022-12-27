use bytestream::{ByteOrder::BigEndian, StreamReader, StreamWriter};
use des::prelude::{MessageBody, MessageKind};
use std::{
    io::{Cursor, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use crate::{FromBytestream, IntoBytestream};

pub const KIND_IPV4: MessageKind = 0x0800;
pub const KIND_IPV6: MessageKind = 0x86DD;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum IpPacket {
    V4(Ipv4Packet),
    V6(Ipv6Packet),
}

#[derive(Debug)]
pub(crate) enum IpPacketRef<'a, 'b> {
    V4(&'a Ipv4Packet),
    V6(&'b Ipv6Packet),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Ipv4Packet {
    pub version: IpVersion,
    pub dscp: u8, // prev tos
    pub enc: u8,
    pub identification: u16,
    pub flags: IpFlags,
    pub fragment_offset: u16,
    pub ttl: u8,
    pub proto: u8,
    pub checksum: u16,

    pub src: Ipv4Addr,
    pub dest: Ipv4Addr,

    pub content: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Ipv6Packet {
    pub version: IpVersion,
    pub traffic_class: u8,
    pub flow_label: u32, // u20
    pub next_header: u8,
    pub hop_limit: u8,

    pub src: Ipv6Addr,
    pub dest: Ipv6Addr,

    pub content: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum IpVersion {
    V4 = 4,
    V6 = 6,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IpFlags {
    pub df: bool,
    pub mf: bool,
}

impl IpPacketRef<'_, '_> {
    pub(crate) fn tos(&self) -> u8 {
        match self {
            Self::V4(v4) => v4.proto,
            Self::V6(v6) => v6.next_header,
        }
    }

    pub(crate) fn content(&self) -> &Vec<u8> {
        match self {
            Self::V4(v4) => &v4.content,
            Self::V6(v6) => &v6.content,
        }
    }

    pub(crate) fn src(&self) -> IpAddr {
        match self {
            Self::V4(v4) => IpAddr::V4(v4.src),
            Self::V6(v6) => IpAddr::V6(v6.src),
        }
    }

    pub(crate) fn dest(&self) -> IpAddr {
        match self {
            Self::V4(v4) => IpAddr::V4(v4.dest),
            Self::V6(v6) => IpAddr::V6(v6.dest),
        }
    }
}

impl IpPacket {
    pub fn version(&self) -> IpVersion {
        if self.is_v4() {
            IpVersion::V4
        } else {
            IpVersion::V6
        }
    }

    pub(crate) fn kind(&self) -> MessageKind {
        if self.is_v4() {
            KIND_IPV4
        } else {
            KIND_IPV6
        }
    }

    pub(crate) fn set_src(&mut self, src: IpAddr) {
        match (self, src) {
            (Self::V4(v4), IpAddr::V4(addr)) => v4.src = addr,
            (Self::V6(v6), IpAddr::V6(addr)) => v6.src = addr,
            _ => unreachable!(),
        }
    }

    pub fn is_v4(&self) -> bool {
        matches!(self, Self::V4(_))
    }

    pub fn is_v6(&self) -> bool {
        matches!(self, Self::V6(_))
    }
}

impl IpFlags {
    fn as_u16(&self) -> u16 {
        (if self.df { 0x010 } else { 0 } | if self.mf { 0x100 } else { 0 }) << 15
    }
}

impl IntoBytestream for Ipv4Packet {
    type Error = std::io::Error;
    fn into_bytestream(&self, bytestream: &mut impl Write) -> Result<(), Self::Error> {
        let byte0 = ((self.version as u8) << 4) | (20 & 0b1111);
        byte0.write_to(bytestream, BigEndian)?;

        let byte1 = (self.dscp << 2) | self.enc;
        byte1.write_to(bytestream, BigEndian)?;

        let len = 20 + self.content.len() as u16;
        len.write_to(bytestream, BigEndian)?;
        self.identification.write_to(bytestream, BigEndian)?;

        let fbyte = self.flags.as_u16() | self.fragment_offset;
        fbyte.write_to(bytestream, BigEndian)?;

        self.ttl.write_to(bytestream, BigEndian)?;
        self.proto.write_to(bytestream, BigEndian)?;
        self.checksum.write_to(bytestream, BigEndian)?;

        u32::from_be_bytes(self.src.octets()).write_to(bytestream, BigEndian)?;
        u32::from_be_bytes(self.dest.octets()).write_to(bytestream, BigEndian)?;

        bytestream.write_all(&self.content)?;
        Ok(())
    }
}

impl IntoBytestream for Ipv6Packet {
    type Error = std::io::Error;
    fn into_bytestream(&self, bytestream: &mut impl Write) -> Result<(), Self::Error> {
        let byte0 = ((self.version as u8) << 4) | (self.traffic_class >> 4);
        byte0.write_to(bytestream, BigEndian)?;

        // [32..24 24..16 16..8 8..0]
        let bytes = self.flow_label.to_be_bytes();
        let byte0 = ((self.traffic_class & 0b1111) << 4) | bytes[1] & 0b1111;
        byte0.write_to(bytestream, BigEndian)?;
        bytes[2].write_to(bytestream, BigEndian)?;
        bytes[3].write_to(bytestream, BigEndian)?;

        let len = self.content.len() as u16;
        len.write_to(bytestream, BigEndian)?;

        for byte in self.src.octets() {
            byte.write_to(bytestream, BigEndian)?;
        }
        for byte in self.dest.octets() {
            byte.write_to(bytestream, BigEndian)?;
        }

        bytestream.write_all(&self.content)?;
        Ok(())
    }
}

impl FromBytestream for Ipv4Packet {
    type Error = std::io::Error;
    fn from_bytestream(bytestream: &mut Cursor<impl AsRef<[u8]>>) -> Result<Self, Self::Error> {
        let byte0 = u8::read_from(bytestream, BigEndian)?;
        let version = byte0 >> 4;
        let version = match version {
            4 => IpVersion::V4,
            6 => IpVersion::V6,
            _ => unimplemented!(),
        };
        // let ihl = byte0 & 0x0f;

        let byte1 = u8::read_from(bytestream, BigEndian)?;
        let dscp = byte1 >> 2;
        let enc = byte1 & 0x03;

        let len = u16::read_from(bytestream, BigEndian)?;
        let identification = u16::read_from(bytestream, BigEndian)?;

        let fword = u16::read_from(bytestream, BigEndian)?;
        let flags = {
            let fbyte = fword >> 15;
            let mut flags = IpFlags {
                mf: false,
                df: false,
            };
            if fbyte & 0b010 != 0 {
                flags.df = true;
            }
            if fbyte & 0b001 != 0 {
                flags.mf = true;
            }
            flags
        };
        let fragment_offset = fword & 0x1fff;

        let ttl = u8::read_from(bytestream, BigEndian)?;
        let proto = u8::read_from(bytestream, BigEndian)?;

        let checksum = u16::read_from(bytestream, BigEndian)?;

        let src = Ipv4Addr::from(u32::read_from(bytestream, BigEndian)?);
        let dest = Ipv4Addr::from(u32::read_from(bytestream, BigEndian)?);

        // fetch rest
        let mut content = Vec::with_capacity(len as usize - 20);
        for _ in 0..(len - 20) {
            content.push(u8::read_from(bytestream, BigEndian)?);
        }

        Ok(Self {
            version,
            // ihl,
            dscp,
            enc,
            // len,
            identification,
            flags,
            fragment_offset,
            ttl,
            proto,
            checksum,
            src,
            dest,
            content,
        })
    }
}

impl FromBytestream for Ipv6Packet {
    type Error = std::io::Error;
    fn from_bytestream(bytestream: &mut Cursor<impl AsRef<[u8]>>) -> Result<Self, Self::Error> {
        let byte0 = u8::read_from(bytestream, BigEndian)?;
        let byte1 = u8::read_from(bytestream, BigEndian)?;
        let byte2 = u8::read_from(bytestream, BigEndian)?;
        let byte3 = u8::read_from(bytestream, BigEndian)?;

        let version = byte0 >> 4;
        let version = match version {
            4 => IpVersion::V4,
            6 => IpVersion::V6,
            _ => unimplemented!(),
        };

        let traffic_class = 0u8 | ((byte0 & 0b1111) << 4) | ((byte0 >> 4) & 0b1111);

        let f2 = byte1 & 0b1111;
        let flow_label = u32::from_be_bytes([0, f2, byte2, byte3]);

        let len = u16::read_from(bytestream, BigEndian)?;
        let next_header = u8::read_from(bytestream, BigEndian)?;
        let hop_limit = u8::read_from(bytestream, BigEndian)?;

        let mut src = [0u8; 16];
        let mut dest = [0u8; 16];
        for i in 0..16 {
            src[i] = u8::read_from(bytestream, BigEndian)?;
        }
        for i in 0..16 {
            dest[i] = u8::read_from(bytestream, BigEndian)?;
        }

        let src = Ipv6Addr::from(src);
        let dest = Ipv6Addr::from(dest);

        // fetch rest
        let mut content = Vec::with_capacity(len as usize);
        for _ in 0..(len - 20) {
            content.push(u8::read_from(bytestream, BigEndian)?);
        }

        Ok(Self {
            version,
            traffic_class,
            flow_label,
            next_header,
            hop_limit,
            src,
            dest,
            content,
        })
    }
}

impl MessageBody for Ipv4Packet {
    fn byte_len(&self) -> usize {
        20 + self.content.len()
    }
}

impl MessageBody for Ipv6Packet {
    fn byte_len(&self) -> usize {
        40 + self.content.len()
    }
}
