use bytestream::{ByteOrder::BigEndian, StreamReader, StreamWriter};
use std::{io::Cursor, net::Ipv4Addr};

use crate::common::{split_off_front, FromBytestreamDepc, IntoBytestreamDepc};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IPPacket {
    pub version: IPVersion,
    pub ihl: u8,
    pub dscp: u8, // prev tos
    pub enc: u8,

    pub len: u16,
    pub identification: u16,
    pub flags: IPFlags,
    pub fragment_offset: u16,

    pub ttl: u8,
    pub proto: u8,
    pub checksum: u16,

    pub src: Ipv4Addr,
    pub dest: Ipv4Addr,
    // ops: IPOps
    pub content: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum IPVersion {
    V4 = 4,
    V6 = 6,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IPFlags {
    df: bool,
    mf: bool,
}

impl IPFlags {
    fn as_u16(&self) -> u16 {
        (if self.df { 0x010 } else { 0 } | if self.mf { 0x100 } else { 0 }) << 15
    }
}

impl IPPacket {}

impl IntoBytestreamDepc for IPPacket {
    type Error = std::io::Error;
    fn into_bytestream(&self, bytestream: &mut Vec<u8>) -> Result<(), Self::Error> {
        let byte0 = ((self.version as u8) << 4) | self.ihl;
        byte0.write_to(bytestream, BigEndian)?;

        let byte1 = (self.dscp << 2) | self.enc;
        byte1.write_to(bytestream, BigEndian)?;

        self.len.write_to(bytestream, BigEndian)?;
        self.identification.write_to(bytestream, BigEndian)?;

        let fbyte = self.flags.as_u16() | self.fragment_offset;
        fbyte.write_to(bytestream, BigEndian)?;

        self.ttl.write_to(bytestream, BigEndian)?;
        self.proto.write_to(bytestream, BigEndian)?;
        self.checksum.write_to(bytestream, BigEndian)?;

        u32::from_be_bytes(self.src.octets()).write_to(bytestream, BigEndian)?;
        u32::from_be_bytes(self.dest.octets()).write_to(bytestream, BigEndian)?;

        bytestream.extend(&self.content);
        Ok(())
    }
}

impl FromBytestreamDepc for IPPacket {
    type Error = std::io::Error;
    fn from_bytestream(bytestream: Vec<u8>) -> Result<Self, Self::Error> {
        let mut cursor = Cursor::new(bytestream);
        let byte0 = u8::read_from(&mut cursor, BigEndian)?;
        let version = byte0 >> 4;
        let version = match version {
            4 => IPVersion::V4,
            6 => IPVersion::V6,
            _ => unimplemented!(),
        };
        let ihl = byte0 & 0x0f;

        let byte1 = u8::read_from(&mut cursor, BigEndian)?;
        let dscp = byte1 >> 2;
        let enc = byte1 & 0x03;

        let len = u16::read_from(&mut cursor, BigEndian)?;
        let identification = u16::read_from(&mut cursor, BigEndian)?;

        let fword = u16::read_from(&mut cursor, BigEndian)?;
        let flags = {
            let fbyte = fword >> 15;
            let mut flags = IPFlags {
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

        let ttl = u8::read_from(&mut cursor, BigEndian)?;
        let proto = u8::read_from(&mut cursor, BigEndian)?;

        let checksum = u16::read_from(&mut cursor, BigEndian)?;

        let src = Ipv4Addr::from(u32::read_from(&mut cursor, BigEndian)?);
        let dest = Ipv4Addr::from(u32::read_from(&mut cursor, BigEndian)?);

        let pos = cursor.position() as usize;

        Ok(Self {
            version,
            ihl,
            dscp,
            enc,
            len,
            identification,
            flags,
            fragment_offset,
            ttl,
            proto,
            checksum,
            src,
            dest,
            content: split_off_front(cursor.into_inner(), pos),
        })
    }
}
