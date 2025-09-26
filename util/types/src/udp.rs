use bytes_io::{
    BE, Bytes, BytesReader, BytesWriter, FromBytes, ReadBytesExt, ToBytes, WriteBytesExt,
};
use std::{
    io::Write,
    ops::{Deref, DerefMut},
};

pub const PROTO_UDP: u8 = 0x11;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UdpPacket {
    pub header: UdpPacketHeader,
    pub content: Bytes,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UdpPacketHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub content_len: u16,
    pub checksum: u16,
}

impl UdpPacket {
    pub fn new(src_port: u16, dst_port: u16, content: impl Into<Bytes>) -> Self {
        let content = content.into();
        Self {
            header: UdpPacketHeader {
                src_port,
                dst_port,
                content_len: content.len() as u16 + 8,
                checksum: 0,
            },
            content,
        }
    }
}

impl Deref for UdpPacket {
    type Target = UdpPacketHeader;
    fn deref(&self) -> &Self::Target {
        &self.header
    }
}

impl DerefMut for UdpPacket {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.header
    }
}

impl ToBytes for UdpPacket {
    type Error = std::io::Error;
    fn to_bytes(&self, stream: &mut BytesWriter) -> Result<(), Self::Error> {
        assert_eq!((self.content.len() + 8) as u16, self.header.content_len);
        self.header.to_bytes(stream)?;
        stream.write_all(&self.content)?;
        Ok(())
    }
}

impl ToBytes for UdpPacketHeader {
    type Error = std::io::Error;
    fn to_bytes(&self, stream: &mut BytesWriter) -> Result<(), Self::Error> {
        stream.write_u16::<BE>(self.src_port)?;
        stream.write_u16::<BE>(self.dst_port)?;
        stream.write_u16::<BE>(self.content_len)?;
        stream.write_u16::<BE>(self.checksum)?;

        Ok(())
    }
}

impl FromBytes for UdpPacket {
    type Error = std::io::Error;
    fn from_bytes(stream: &mut BytesReader) -> Result<Self, Self::Error> {
        let header = UdpPacketHeader::from_bytes(stream)?;
        let content = stream.copy_to_bytes((header.content_len - 8) as usize);

        Ok(Self { header, content })
    }
}

impl FromBytes for UdpPacketHeader {
    type Error = std::io::Error;
    fn from_bytes(stream: &mut BytesReader) -> Result<Self, Self::Error> {
        let src_port = stream.read_u16::<BE>()?;
        let dst_port = stream.read_u16::<BE>()?;
        let content_len = stream.read_u16::<BE>()?;
        let checksum = stream.read_u16::<BE>()?;

        Ok(Self {
            src_port,
            dst_port,
            content_len,
            checksum,
        })
    }
}

#[cfg(test)]
mod tests {
    use bytes_io::assert_encoding_e2e;
    use rand::{Rng, rng};

    use super::*;

    impl UdpPacket {
        fn random() -> Self {
            let bytes = std::iter::repeat_with(|| rng().random())
                .take((rng().random::<u32>() % 1500) as usize)
                .collect::<Bytes>();
            Self {
                header: UdpPacketHeader::random(bytes.len() as u16 + 8),
                content: bytes,
            }
        }
    }

    impl UdpPacketHeader {
        fn random(content_len: u16) -> Self {
            Self {
                src_port: rng().random(),
                dst_port: rng().random(),
                content_len,
                checksum: rng().random(),
            }
        }
    }

    #[test]
    fn e2e_encoding_fuzz() {
        let fuzzed = std::iter::repeat_with(UdpPacket::random)
            .take(100)
            .collect::<Vec<_>>();

        assert_encoding_e2e(&fuzzed);
    }
}
