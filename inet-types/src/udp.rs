use super::{FromBytestream, IntoBytestream};
use bytestream::{ByteOrder::BigEndian, StreamReader, StreamWriter};
use std::io::{Cursor, Read, Write};

pub const PROTO_UDP: u8 = 0x11;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UDPPacket {
    pub src_port: u16,
    pub dest_port: u16,
    // pub length: u16,
    pub checksum: u16,

    pub content: Vec<u8>,
}

impl IntoBytestream for UDPPacket {
    type Error = std::io::Error;
    fn into_bytestream(&self, bytestream: &mut impl Write) -> Result<(), Self::Error> {
        self.src_port.write_to(bytestream, BigEndian)?;
        self.dest_port.write_to(bytestream, BigEndian)?;
        (8 + self.content.len() as u16).write_to(bytestream, BigEndian)?;
        self.checksum.write_to(bytestream, BigEndian)?;

        bytestream.write_all(&self.content)?;
        Ok(())
    }
}

impl FromBytestream for UDPPacket {
    type Error = std::io::Error;
    fn from_bytestream(bytestream: &mut Cursor<impl AsRef<[u8]>>) -> Result<Self, Self::Error> {
        let src_port = u16::read_from(bytestream, BigEndian)?;
        let dest_port = u16::read_from(bytestream, BigEndian)?;
        let length = u16::read_from(bytestream, BigEndian)?;
        let checksum = u16::read_from(bytestream, BigEndian)?;

        let mut buf = Vec::new();
        bytestream.read_to_end(&mut buf)?;

        assert_eq!(buf.len() as u16, length - 8);

        Ok(Self {
            src_port,
            dest_port,
            checksum,
            content: buf,
        })
    }
}
