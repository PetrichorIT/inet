use bytepack::{
    BytestreamReader, BytestreamWriter, FromBytestream, ReadBytesExt, ToBytestream, WriteBytesExt,
    BE,
};
use bytes_io::{BytesReader, BytesWriter, FromBytes, ToBytes};
use std::io::{Read, Write};

pub const PROTO_UDP: u8 = 0x11;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UdpPacket {
    pub src_port: u16,
    pub dst_port: u16,
    pub checksum: u16,
    pub content: Vec<u8>,
}

impl ToBytestream for UdpPacket {
    type Error = std::io::Error;
    fn to_bytestream(&self, stream: &mut BytestreamWriter) -> Result<(), Self::Error> {
        stream.write_u16::<BE>(self.src_port)?;
        stream.write_u16::<BE>(self.dst_port)?;
        stream.write_u16::<BE>(self.content.len() as u16 + 8)?;
        stream.write_u16::<BE>(self.checksum)?;

        stream.write_all(&self.content)?;
        Ok(())
    }
}

impl ToBytes for UdpPacket {
    type Error = std::io::Error;
    fn to_bytes(&self, stream: &mut BytesWriter) -> Result<(), Self::Error> {
        stream.write_u16::<BE>(self.src_port)?;
        stream.write_u16::<BE>(self.dst_port)?;
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
        let dst_port = stream.read_u16::<BE>()?;
        let len = stream.read_u16::<BE>()?;
        let checksum = stream.read_u16::<BE>()?;

        let mut buf = vec![0; (len - 8) as usize];
        stream.read_exact(&mut buf)?;

        Ok(Self {
            src_port,
            dst_port,
            checksum,
            content: buf,
        })
    }
}

impl FromBytes for UdpPacket {
    type Error = std::io::Error;
    fn from_bytes(stream: &mut BytesReader) -> Result<Self, Self::Error> {
        let src_port = stream.read_u16::<BE>()?;
        let dst_port = stream.read_u16::<BE>()?;
        let len = stream.read_u16::<BE>()?;
        let checksum = stream.read_u16::<BE>()?;

        let mut buf = vec![0; (len - 8) as usize];
        stream.read_exact(&mut buf)?;

        Ok(Self {
            src_port,
            dst_port,
            checksum,
            content: buf,
        })
    }
}

#[cfg(test)]
mod tests {
    use bytes_io::assert_encoding_e2e;
    use rand::{rng, Rng};

    use super::*;

    #[test]
    fn e2e_encoding_fuzz() {
        let fuzzed = std::iter::repeat_with(|| UdpPacket {
            src_port: rng().random(),
            dst_port: rng().random(),
            checksum: rng().random(),
            content: std::iter::repeat_with(|| rng().random())
                .take((rng().random::<u32>() % 1500) as usize)
                .collect(),
        })
        .take(100)
        .collect::<Vec<_>>();

        assert_encoding_e2e(&fuzzed);
    }
}
