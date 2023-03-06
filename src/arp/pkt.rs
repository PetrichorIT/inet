use crate::interface2::MacAddress;
use crate::{FromBytestream, IntoBytestream};
use bytestream::ByteOrder::BigEndian;
use bytestream::{StreamReader, StreamWriter};
use des::prelude::*;
use std::{
    io::{Cursor, Write},
    net::Ipv4Addr,
};

pub const KIND_ARP: MessageKind = 0x0806;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ARPPacket {
    pub htype: u16,
    pub ptype: u16,
    pub operation: ARPOperation,
    pub src_haddr: MacAddress,
    pub dest_haddr: MacAddress,
    pub src_paddr: Ipv4Addr,
    pub dest_paddr: Ipv4Addr,
}

primitve_enum_repr! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub enum ARPOperation {
        type Repr = u16;

        Request = 1,
        Response = 2,
    };
}

impl IntoBytestream for ARPPacket {
    type Error = std::io::Error;
    fn into_bytestream(&self, bytestream: &mut impl Write) -> Result<(), Self::Error> {
        self.htype.write_to(bytestream, BigEndian)?;
        self.ptype.write_to(bytestream, BigEndian)?;

        // haddr_size
        6u8.write_to(bytestream, BigEndian)?;
        // paddr_size
        4u8.write_to(bytestream, BigEndian)?;

        self.operation.into_bytestream(bytestream)?;

        self.src_haddr.into_bytestream(bytestream)?;
        self.src_paddr.into_bytestream(bytestream)?;

        self.dest_haddr.into_bytestream(bytestream)?;
        self.dest_paddr.into_bytestream(bytestream)?;

        Ok(())
    }
}

impl IntoBytestream for ARPOperation {
    type Error = std::io::Error;
    fn into_bytestream(&self, bytestream: &mut impl Write) -> Result<(), Self::Error> {
        self.to_raw().write_to(bytestream, BigEndian)
    }
}

impl FromBytestream for ARPPacket {
    type Error = std::io::Error;
    fn from_bytestream(bytestream: &mut Cursor<impl AsRef<[u8]>>) -> Result<Self, Self::Error> {
        let htype = u16::read_from(bytestream, BigEndian)?;
        let ptype = u16::read_from(bytestream, BigEndian)?;

        let hlen = u8::read_from(bytestream, BigEndian)?;
        assert_eq!(hlen, 6);
        let plen = u8::read_from(bytestream, BigEndian)?;
        assert_eq!(plen, 4);

        let operation = ARPOperation::from_bytestream(bytestream)?;
        let src_haddr = MacAddress::from_bytestream(bytestream)?;
        let src_paddr = Ipv4Addr::from_bytestream(bytestream)?;
        let dest_haddr = MacAddress::from_bytestream(bytestream)?;
        let dest_paddr = Ipv4Addr::from_bytestream(bytestream)?;

        Ok(ARPPacket {
            htype,
            ptype,
            operation,
            src_haddr,
            dest_haddr,
            src_paddr,
            dest_paddr,
        })
    }
}

impl FromBytestream for ARPOperation {
    type Error = std::io::Error;
    fn from_bytestream(bytestream: &mut Cursor<impl AsRef<[u8]>>) -> Result<Self, Self::Error> {
        let tag = u16::read_from(bytestream, BigEndian)?;
        Ok(Self::from_raw(tag).unwrap())
    }
}

impl MessageBody for ARPPacket {
    fn byte_len(&self) -> usize {
        28
    }
}
