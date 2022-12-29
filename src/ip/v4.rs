use crate::{FromBytestream, IntoBytestream};
use bytestream::{ByteOrder::BigEndian, StreamReader, StreamWriter};
use des::net::message::MessageBody;
use std::{
    io::{Cursor, Write},
    net::Ipv4Addr,
};

use super::IpVersion;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Ipv4Packet {
    pub version: IpVersion,
    pub dscp: u8, // prev tos
    pub enc: u8,
    pub identification: u16,
    pub flags: Ipv4Flags,
    pub fragment_offset: u16,
    pub ttl: u8,
    pub proto: u8,
    pub checksum: u16,

    pub src: Ipv4Addr,
    pub dest: Ipv4Addr,

    pub content: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ipv4Flags {
    pub df: bool,
    pub mf: bool,
}

impl Ipv4Flags {
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
            let mut flags = Ipv4Flags {
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
impl MessageBody for Ipv4Packet {
    fn byte_len(&self) -> usize {
        20 + self.content.len()
    }
}
