use std::io::{Error, ErrorKind, Read, Write};
use std::net::IpAddr;
use std::ops::Deref;

use bytepack::{FromBytestream, ToBytestream};
use des::prelude::MessageBody;

mod util;
mod v4;
mod v6;

pub use self::util::*;
pub use self::v4::Ipv4Header;
pub use self::v6::Ipv6Header;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpHeader {
    V4(Ipv4Header),
    V6(Ipv6Header),
}

impl IpHeader {
    #[must_use]
    pub fn is_v4(&self) -> bool {
        matches!(self, Self::V4(_))
    }

    #[must_use]
    pub fn is_v6(&self) -> bool {
        matches!(self, Self::V6(_))
    }

    pub fn payload_length(&self) -> u16 {
        match self {
            Self::V4(ref v4) => v4.len - 20,
            Self::V6(ref v6) => v6.len, // - extension headers,
        }
    }

    pub fn set_payload_len(&mut self, len: u16) {
        match self {
            Self::V4(v4) => v4.len = 20 + len,
            Self::V6(v6) => v6.len = len,
        }
    }

    pub fn src(&self) -> IpAddr {
        match self {
            Self::V4(ref v4) => v4.src.into(),
            Self::V6(ref v6) => v6.src.into(),
        }
    }

    pub fn dest(&self) -> IpAddr {
        match self {
            Self::V4(ref v4) => v4.dest.into(),
            Self::V6(ref v6) => v6.dest.into(),
        }
    }

    pub fn tos(&self) -> u8 {
        match self {
            Self::V4(ref v4) => v4.proto,
            Self::V6(ref v6) => v6.next_header,
        }
    }

    pub fn reverse(&self) -> IpHeader {
        match self {
            Self::V4(ref v4) => Self::V4(v4.reverse()),
            Self::V6(ref v6) => Self::V6(v6.reverse()),
        }
    }
}

impl From<Ipv4Header> for IpHeader {
    fn from(header: Ipv4Header) -> Self {
        IpHeader::V4(header)
    }
}

impl From<Ipv6Header> for IpHeader {
    fn from(header: Ipv6Header) -> Self {
        IpHeader::V6(header)
    }
}

impl MessageBody for IpHeader {
    fn byte_len(&self) -> usize {
        match self {
            Self::V4(ref v4) => v4.byte_len(),
            Self::V6(ref v6) => v6.byte_len(),
        }
    }
}

pub struct IpPacket {
    pub header: IpHeader,
    pub payload: Vec<u8>,
}

impl IpPacket {
    pub fn response(&self, payload: Vec<u8>) -> IpPacket {
        let mut header = self.header.reverse();
        header.set_payload_len(payload.len() as u16);
        IpPacket { header, payload }
    }
}

impl Deref for IpPacket {
    type Target = IpHeader;
    fn deref(&self) -> &Self::Target {
        &self.header
    }
}

impl MessageBody for IpPacket {
    fn byte_len(&self) -> usize {
        self.header.byte_len() + self.payload.len()
    }
}

pub struct Ipv4Packet {
    pub header: Ipv4Header,
    pub payload: Vec<u8>,
}

impl Ipv4Packet {
    pub fn response(&self, payload: Vec<u8>) -> Ipv4Packet {
        let mut header = self.header.reverse();
        header.len = (20 + self.payload.len()) as u16;
        Ipv4Packet { header, payload }
    }
}

impl Deref for Ipv4Packet {
    type Target = Ipv4Header;
    fn deref(&self) -> &Self::Target {
        &self.header
    }
}

impl MessageBody for Ipv4Packet {
    fn byte_len(&self) -> usize {
        self.header.byte_len() + self.payload.len()
    }
}

impl ToBytestream for Ipv4Packet {
    type Error = Error;
    fn to_bytestream(&self, stream: &mut bytepack::BytestreamWriter) -> Result<(), Self::Error> {
        if self.header.len != (20 + self.payload.len()) as u16 {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "Ipv4 header length does not match payload length",
            ));
        }

        self.header.to_bytestream(stream)?;
        stream.write_all(&self.payload)?;

        Ok(())
    }
}

impl FromBytestream for Ipv4Packet {
    type Error = Error;
    fn from_bytestream(stream: &mut bytepack::BytestreamReader) -> Result<Self, Self::Error> {
        let header = Ipv4Header::from_bytestream(stream)?;
        let mut payload = vec![0; (header.len - 20) as usize];
        stream.read_exact(&mut payload)?;
        Ok(Ipv4Packet { header, payload })
    }
}
