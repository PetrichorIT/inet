use std::{
    io,
    net::{Ipv4Addr, Ipv6Addr},
    ops::{Deref, DerefMut},
};

use byteorder::{ReadBytesExt, BE};
use bytes::{Buf, Bytes};

/// A
pub trait FromBytes: Sized {
    /// A
    type Error;

    /// A
    fn from_bytes(stream: &mut BytesReader) -> Result<Self, Self::Error>;

    /// A
    fn read_from(bytes: &mut Bytes) -> Result<Self, Self::Error> {
        let available = bytes.split_off(0);

        let mut reader = BytesReader::new(available);
        let result = Self::from_bytes(&mut reader)?;

        *bytes = reader.bytes;
        Ok(result)
    }
}

/// A
#[derive(Debug)]
pub struct BytesReader {
    bytes: Bytes,
}

impl BytesReader {
    /// A
    pub fn new(bytes: Bytes) -> Self {
        Self { bytes }
    }

    /// A
    pub fn peek(&self) -> &[u8] {
        &self.bytes
    }

    /// A
    pub fn extract(&mut self, n: usize) -> io::Result<Self> {
        if self.bytes.remaining() < n {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "invalid substream length",
            ));
        }
        let bytes = self.bytes.copy_to_bytes(n);
        Ok(Self { bytes })
    }
}

impl Deref for BytesReader {
    type Target = Bytes;
    fn deref(&self) -> &Self::Target {
        &self.bytes
    }
}

impl DerefMut for BytesReader {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.bytes
    }
}

impl io::Read for BytesReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = buf.len().min(self.bytes.remaining());
        self.bytes.copy_to_slice(&mut buf[..n]);
        Ok(n)
    }
}

//# Impls

impl FromBytes for Ipv4Addr {
    type Error = std::io::Error;
    fn from_bytes(bytestream: &mut BytesReader) -> Result<Self, Self::Error> {
        Ok(Ipv4Addr::from(bytestream.read_u32::<BE>()?))
    }
}

impl FromBytes for Ipv6Addr {
    type Error = std::io::Error;
    fn from_bytes(bytestream: &mut BytesReader) -> Result<Self, Self::Error> {
        Ok(Ipv6Addr::from(bytestream.read_u128::<BE>()?))
    }
}

#[cfg(test)]
mod tests {
    use std::io::ErrorKind;

    use byteorder::{ReadBytesExt, BE};
    use bytes::TryGetError;

    use super::*;

    #[test]
    fn buf_read() {
        let mut bytes = BytesReader::new(Bytes::from_static(&[
            0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8,
        ]));
        assert_eq!(bytes.get_u32(), 0x01020304);
        assert_eq!(bytes.get_u32(), 0x05060708);

        assert_eq!(
            bytes.try_get_u8(),
            Err(TryGetError {
                requested: 1,
                available: 0
            })
        )
    }

    #[test]
    fn io_read() -> io::Result<()> {
        let bytes = Bytes::from_static(&[0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8]);
        let mut reader = BytesReader::new(bytes);
        assert_eq!(reader.read_u32::<BE>()?, 0x01020304);
        assert_eq!(reader.read_u32::<BE>()?, 0x05060708);
        assert_eq!(
            reader.read_u32::<BE>().unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof,
        );
        Ok(())
    }

    #[test]
    fn extract() -> io::Result<()> {
        let bytes = Bytes::from_static(&[0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8]);
        let mut reader = BytesReader::new(bytes);
        assert_eq!(reader.get_u8(), 0x1);

        let mut extr = reader.extract(6)?;
        assert_eq!(extr.get_u32(), 0x02030405);
        assert_eq!(extr.get_u16(), 0x0607);
        assert_eq!(extr.remaining(), 0);

        assert_eq!(reader.get_u8(), 0x08);
        assert_eq!(reader.remaining(), 0);

        Ok(())
    }

    #[test]
    fn extract_failure() {
        let bytes = Bytes::from_static(&[0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8]);
        let mut reader = BytesReader::new(bytes);

        let error = reader.extract(10).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::UnexpectedEof);
    }

    #[test]
    fn peek() -> io::Result<()> {
        let bytes = Bytes::from_static(&[0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8]);
        let reader = BytesReader::new(bytes);

        assert_eq!(reader.peek(), &[0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8]);
        assert_eq!(reader.peek().read_u32::<BE>()?, 0x01020304);

        Ok(())
    }

    struct U32x2 {
        inner: [u32; 2],
    }

    impl FromBytes for U32x2 {
        type Error = io::Error;
        fn from_bytes(stream: &mut BytesReader) -> Result<Self, Self::Error> {
            let a0 = stream.get_u32();
            let a1 = stream.get_u32();
            Ok(U32x2 { inner: [a0, a1] })
        }
    }

    #[test]
    fn trait_read_from() -> io::Result<()> {
        let mut bytes = Bytes::from_static(&[0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9]);
        let value = U32x2::read_from(&mut bytes)?;
        assert_eq!(value.inner, [0x01020304, 0x05060708]);
        assert_eq!(bytes.remaining(), 1);
        assert_eq!(&bytes[..], &[0x09]);
        Ok(())
    }
}
