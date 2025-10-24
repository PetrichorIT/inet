use std::io::Write;

use bytes_io::{BE, Bytes, BytesWriter, ToBytes, WriteBytesExt};

use crate::iface::MacAddress;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EthernetFrame {
    pub src: MacAddress,
    pub dst: MacAddress,
    pub ethertyp: u16,
    pub content: Bytes,
}

impl ToBytes for EthernetFrame {
    type Error = std::io::Error;
    fn to_bytes(&self, writer: &mut BytesWriter) -> Result<(), Self::Error> {
        self.src.to_bytes(writer)?;
        self.dst.to_bytes(writer)?;
        writer.write_u16::<BE>(self.ethertyp)?;
        writer.write_all(&self.content)?;
        writer.write_all(&[0x00; 4])?;

        Ok(())
    }
}
