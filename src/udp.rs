use std::io::Cursor;

use bytestream::{ByteOrder::BigEndian, StreamReader, StreamWriter};

use crate::common::{split_off_front, FromBytestreamDepc, IntoBytestreamDepc};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UDPPacket {
    pub src_port: u16,
    pub dest_port: u16,
    pub length: u16,
    pub checksum: u16,

    pub content: Vec<u8>,
}

impl IntoBytestreamDepc for UDPPacket {
    type Error = std::io::Error;
    fn into_bytestream(&self, bytestream: &mut Vec<u8>) -> Result<(), Self::Error> {
        self.src_port.write_to(bytestream, BigEndian)?;
        self.dest_port.write_to(bytestream, BigEndian)?;
        self.length.write_to(bytestream, BigEndian)?;
        self.checksum.write_to(bytestream, BigEndian)?;

        bytestream.extend(&self.content);
        Ok(())
    }
}

impl FromBytestreamDepc for UDPPacket {
    type Error = std::io::Error;
    fn from_bytestream(bytestream: Vec<u8>) -> Result<Self, Self::Error> {
        let mut cursor = Cursor::new(bytestream);
        let src_port = u16::read_from(&mut cursor, BigEndian)?;
        let dest_port = u16::read_from(&mut cursor, BigEndian)?;
        let length = u16::read_from(&mut cursor, BigEndian)?;
        let checksum = u16::read_from(&mut cursor, BigEndian)?;

        let pos = cursor.position() as usize;

        Ok(Self {
            src_port,
            dest_port,
            length,
            checksum,

            content: split_off_front(cursor.into_inner(), pos),
        })
    }
}
