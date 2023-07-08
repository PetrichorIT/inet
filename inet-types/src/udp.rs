use bytepack::{
    BytestreamReader, BytestreamWriter, FromBytestream, ReadBytesExt, ToBytestream, WriteBytesExt,
    BE,
};
use std::io::{Read, Write};

pub const PROTO_UDP: u8 = 0x11;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UdpPacket {
    pub src_port: u16,
    pub dest_port: u16,
    pub checksum: u16,
    pub content: Vec<u8>,
}

impl ToBytestream for UdpPacket {
    type Error = std::io::Error;
    fn to_bytestream(&self, stream: &mut BytestreamWriter) -> Result<(), Self::Error> {
        stream.write_u16::<BE>(self.src_port)?;
        stream.write_u16::<BE>(self.dest_port)?;
        stream.write_u16::<BE>(self.content.len() as u16 + 8)?;
        stream.write_u16::<BE>(self.checksum)?;

        stream.write_all(&self.content)?;
        Ok(())
    }
}

impl FromBytestream for UdpPacket {
    type Error = std::io::Error;
    fn from_bytestream(stream: &mut BytestreamReader) -> Result<Self, Self::Error> {
        let src_port = stream.read_u16::<BE>()?;
        let dest_port = stream.read_u16::<BE>()?;
        let len = stream.read_u16::<BE>()?;
        let checksum = stream.read_u16::<BE>()?;

        let mut buf = vec![0; (len - 8) as usize];
        stream.read_exact(&mut buf)?;

        Ok(Self {
            src_port,
            dest_port,
            checksum,
            content: buf,
        })
    }
}
