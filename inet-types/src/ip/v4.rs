use crate::{FromBytestream, IntoBytestream};
use bytestream::{ByteOrder::BigEndian, StreamReader, StreamWriter};
use des::net::message::MessageBody;
use std::{
    io::{Cursor, Error, ErrorKind, Write},
    net::Ipv4Addr,
};

use super::IpVersion;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Ipv4Packet {
    // pub version: IpVersion,
    pub dscp: u8, // prev tos
    pub enc: u8,
    pub identification: u16,
    pub flags: Ipv4Flags,
    pub fragment_offset: u16,
    pub ttl: u8,
    pub proto: u8,
    // pub checksum: u16,
    pub src: Ipv4Addr,
    pub dest: Ipv4Addr,

    pub content: Vec<u8>,
}

impl Ipv4Packet {
    pub const EMPTY: Ipv4Packet = Ipv4Packet {
        dscp: 0,
        enc: 0,
        identification: 0,
        flags: Ipv4Flags {
            df: false,
            mf: false,
        },
        fragment_offset: 0,
        ttl: 64,
        proto: 0,
        src: Ipv4Addr::UNSPECIFIED,
        dest: Ipv4Addr::UNSPECIFIED,
        content: Vec::new(),
    };

    pub fn reverse(&self) -> Ipv4Packet {
        Ipv4Packet {
            dscp: self.dscp,
            enc: self.enc,
            identification: self.identification,
            flags: Ipv4Flags {
                df: self.flags.df,
                mf: false,
            },
            fragment_offset: 0,
            ttl: 64,
            proto: self.proto,
            src: self.dest,
            dest: self.src,
            content: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ipv4Flags {
    pub df: bool,
    pub mf: bool,
}

impl Ipv4Flags {
    fn as_u16(self) -> u16 {
        let pat = (if self.df { 0b010u16 } else { 0u16 } | if self.mf { 0b100u16 } else { 0u16 });
        pat << 13u16
    }
}

impl IntoBytestream for Ipv4Packet {
    type Error = std::io::Error;
    fn to_bytestream(&self, bytestream: &mut impl Write) -> Result<(), Self::Error> {
        let byte0 = 0b0100_0101u8;
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

        // TODO: make checksum
        0u16.write_to(bytestream, BigEndian)?;

        u32::from_be_bytes(self.src.octets()).write_to(bytestream, BigEndian)?;
        u32::from_be_bytes(self.dest.octets()).write_to(bytestream, BigEndian)?;

        bytestream.write_all(&self.content)?;
        Ok(())
    }
}

impl FromBytestream for Ipv4Packet {
    type Error = std::io::Error;
    fn from_bytestream(bytestream: &mut Cursor<impl AsRef<[u8]>>) -> Result<Self, Self::Error> {
        let byte0 = u8::read_from(bytestream, BigEndian)?;
        let version = byte0 >> 4;
        let _version = match version {
            4 => IpVersion::V4,
            6 => {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    "ipv4 packet expeced, got ipv6 flag",
                ))
            }
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
            let fbyte = fword >> 13;
            let mut flags = Ipv4Flags {
                mf: false,
                df: false,
            };
            if fbyte & 0b100 != 0 {
                flags.mf = true;
            }
            if fbyte & 0b010 != 0 {
                flags.df = true;
            }
            flags
        };
        let fragment_offset = fword & 0x1fff;

        let ttl = u8::read_from(bytestream, BigEndian)?;
        let proto = u8::read_from(bytestream, BigEndian)?;

        let _checksum = u16::read_from(bytestream, BigEndian)?;
        // TODO: check checksum

        let src = Ipv4Addr::from(u32::read_from(bytestream, BigEndian)?);
        let dest = Ipv4Addr::from(u32::read_from(bytestream, BigEndian)?);

        // fetch rest
        let mut content = Vec::with_capacity(len as usize - 20);
        for _ in 0..(len - 20) {
            content.push(u8::read_from(bytestream, BigEndian)?);
        }

        Ok(Self {
            // ihl,
            dscp,
            enc,
            // len,
            identification,
            flags,
            fragment_offset,
            ttl,
            proto,
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

impl IntoBytestream for Ipv4Addr {
    type Error = std::io::Error;
    fn to_bytestream(&self, bytestream: &mut impl Write) -> Result<(), Self::Error> {
        bytestream.write_all(&self.octets())
    }
}

impl FromBytestream for Ipv4Addr {
    type Error = std::io::Error;
    fn from_bytestream(bytestream: &mut Cursor<impl AsRef<[u8]>>) -> Result<Self, Self::Error> {
        Ok(Ipv4Addr::from(u32::read_from(bytestream, BigEndian)?))
    }
}
