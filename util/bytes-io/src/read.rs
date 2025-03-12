use std::{
    fmt::Debug,
    io::{self, Cursor},
    net::{Ipv4Addr, Ipv6Addr},
    ops::{Deref, DerefMut},
};

use byteorder::{ReadBytesExt, BE};
use bytes::Buf;

/// A
pub trait FromBytes: Sized {
    /// A
    type Error;

    /// A
    fn from_bytes(stream: &mut BytesReader) -> Result<Self, Self::Error>;

    /// A
    ///
    /// Will partially consume the buffer on error
    fn read_from<B: Buf>(bytes: &mut B) -> Result<Self, Self::Error> {
        let mut cursor = Cursor::new(bytes.chunk());
        let mut reader = BytesReader::new(&mut cursor);
        let result = Self::from_bytes(&mut reader)?;
        bytes.advance(cursor.position() as usize);
        Ok(result)
    }

    /// A
    fn peek_from<B: Buf>(bytes: B) -> Result<Self, Self::Error> {
        let mut cursor = Cursor::new(bytes.chunk());
        let mut reader = BytesReader::new(&mut cursor);
        let result = Self::from_bytes(&mut reader)?;
        Ok(result)
    }
}

/// A
pub struct BytesReader<'a> {
    bytes: &'a mut dyn Buf,
}

impl<'a> BytesReader<'a> {
    /// A
    pub fn new(bytes: &'a mut dyn Buf) -> Self {
        Self { bytes }
    }

    /// A
    pub fn peek(&self) -> &[u8] {
        self.bytes.chunk()
    }

    /// A
    pub fn extract<R>(
        &mut self,
        n: usize,
        f: impl FnOnce(&mut BytesReader<'_>) -> io::Result<R>,
    ) -> io::Result<R> {
        if self.bytes.remaining() < n {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "invalid substream length",
            ));
        };

        // for Bytes this copy is shallow ref inc
        let mut subslice = self.bytes.copy_to_bytes(n);
        let mut reader = BytesReader::new(&mut subslice);
        let result = f(&mut reader);

        // TODO: should we check for remaining bytes in extracted subslice?

        result
    }
}

impl<'a> Deref for BytesReader<'a> {
    type Target = &'a mut dyn Buf;
    fn deref(&self) -> &Self::Target {
        &self.bytes
    }
}
impl DerefMut for BytesReader<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.bytes
    }
}

impl io::Read for BytesReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = buf.len().min(self.bytes.remaining());
        self.bytes.copy_to_slice(&mut buf[..n]);
        Ok(n)
    }
}

impl Debug for BytesReader<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BytesReader").finish()
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
    use byteorder::{ReadBytesExt, BE};
    use bytes::Bytes;
    use std::io::ErrorKind;

    use super::*;

    #[test]
    fn buf_read() {
        let mut bytes = Bytes::from_static(&[0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8]);
        let mut reader = BytesReader::new(&mut bytes);

        assert_eq!(reader.get_u8(), 1);
        assert_eq!(reader.get_u8(), 2);
        assert_eq!(reader.remaining(), 6);
    }

    #[test]
    fn io_read() -> io::Result<()> {
        let mut bytes = Bytes::from_static(&[0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8]);
        let mut reader = BytesReader::new(&mut bytes);
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
        let mut bytes = Bytes::from_static(&[0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8]);
        let mut reader = BytesReader::new(&mut bytes);
        assert_eq!(reader.read_u8()?, 0x1);

        reader.extract(6, |extr| {
            assert_eq!(extr.read_u32::<BE>()?, 0x02030405);
            assert_eq!(extr.read_u16::<BE>()?, 0x0607);
            assert_eq!(extr.remaining(), 0);
            Ok(())
        })?;

        assert_eq!(reader.read_u8()?, 0x08);
        assert_eq!(reader.remaining(), 0);

        Ok(())
    }

    #[test]
    fn extract_failure() {
        let mut bytes = Bytes::from_static(&[0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8]);
        let mut reader = BytesReader::new(&mut bytes);

        let error = reader.extract(10, |_| Ok(())).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::UnexpectedEof);
    }

    #[test]
    fn peek() -> io::Result<()> {
        let mut bytes = Bytes::from_static(&[0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8]);
        let reader = BytesReader::new(&mut bytes);

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
            let a0 = stream.read_u32::<BE>()?;
            let a1 = stream.read_u32::<BE>()?;
            Ok(U32x2 { inner: [a0, a1] })
        }
    }

    #[test]
    fn trait_read_from_bytes() -> io::Result<()> {
        let mut bytes = Bytes::from_static(&[0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9]);
        let value = U32x2::read_from(&mut bytes)?;
        assert_eq!(value.inner, [0x01020304, 0x05060708]);
        assert_eq!(bytes.remaining(), 1);
        assert_eq!(&bytes[..], &[0x09]);
        Ok(())
    }

    #[test]
    fn trait_read_from() -> io::Result<()> {
        let mut bytes = &[1, 2, 3, 4, 5, 6, 7, 8, 9][..];
        let value = U32x2::read_from(&mut bytes)?;
        assert_eq!(value.inner, [0x01020304, 0x05060708]);
        assert_eq!(bytes, &[9]);
        Ok(())
    }

    #[test]
    fn trait_read_from_vec() {
        let buf = vec![1, 2u8, 3, 4, 5, 6, 7, 8, 9];
        let _ = U32x2::read_from(&mut &buf[..]);
    }
}
