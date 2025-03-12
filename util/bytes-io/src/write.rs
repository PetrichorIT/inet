use std::{
    fmt::Debug,
    io::{self, Write},
    mem,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    ops::{Deref, DerefMut},
};

use bytes::{BufMut, Bytes, BytesMut};

/// A
pub trait ToBytes {
    ///  A
    type Error;

    /// A
    fn to_bytes(&self, writer: &mut BytesWriter) -> Result<(), Self::Error>;

    /// A
    fn write_to<B: BufMut + AsMut<[u8]>>(&self, bytes: &mut B) -> Result<usize, Self::Error> {
        self.write_to_limit(bytes, usize::MAX)
    }

    /// A
    fn write_to_limit<B: BufMut + AsMut<[u8]>>(
        &self,
        bytes: &mut B,
        limit: usize,
    ) -> Result<usize, Self::Error> {
        let initial = bytes.as_mut().len();
        let mut writer = BytesWriter {
            limit,
            markers: 0,
            bytes,
        };
        self.to_bytes(&mut writer)?;
        drop(writer);
        let n = bytes.as_mut().len() - initial;
        Ok(n)
    }

    /// A
    fn write_to_bytes_mut(&self) -> Result<BytesMut, Self::Error> {
        let mut bytes = BytesMut::new();
        self.write_to(&mut bytes)?;
        Ok(bytes)
    }

    /// A
    fn write_to_bytes(&self) -> Result<Bytes, Self::Error> {
        let mut bytes = BytesMut::new();
        self.write_to(&mut bytes)?;
        Ok(bytes.freeze())
    }

    /// A
    fn write_to_vec(&self) -> Result<Vec<u8>, Self::Error> {
        let mut bytes = Vec::new();
        self.write_to(&mut bytes)?;
        Ok(bytes)
    }
}

/// A
pub struct BytesWriter<'a> {
    limit: usize,
    markers: usize,
    bytes: &'a mut dyn Writable,
}

/// A
pub trait Writable: BufMut + AsMut<[u8]> {}
impl<B: BufMut + AsMut<[u8]>> Writable for B {}

/// A
#[derive(Debug)]
#[must_use]
pub struct Marker {
    pos: usize,
    len: usize,
}

impl<'a> BytesWriter<'a> {
    /// A
    pub fn new(bytes: &'a mut dyn Writable, limit: usize) -> Self {
        BytesWriter {
            limit,
            markers: 0,
            bytes,
        }
    }

    /// A
    pub fn marker<T>(&mut self) -> Marker {
        let pos = self.bytes.as_mut().len();
        let len = mem::size_of::<T>();
        self.bytes.put_bytes(0x00, len);
        self.markers += 1;
        Marker { pos, len }
    }

    /// A
    pub fn bytes_written_since(&mut self, marker: &Marker) -> usize {
        self.bytes.as_mut().len() - (marker.pos + marker.len)
    }

    /// A
    pub fn apply(&mut self, marker: Marker) -> &mut [u8] {
        self.markers -= 1;
        let slice = &mut self.bytes.as_mut()[marker.pos..marker.pos + marker.len];
        slice
    }
}

impl Drop for BytesWriter<'_> {
    fn drop(&mut self) {
        assert_eq!(
            self.markers, 0,
            "unapplied markers exist, bytestream not complete anymore"
        );
    }
}

impl<'a> Deref for BytesWriter<'a> {
    type Target = &'a mut dyn Writable;
    fn deref(&self) -> &Self::Target {
        &self.bytes
    }
}

impl DerefMut for BytesWriter<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.bytes
    }
}

impl io::Write for BytesWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.len() > self.limit {
            return Err(io::Error::new(io::ErrorKind::WriteZero, "buffer overflow"));
        }
        self.bytes.put_slice(&buf);
        self.limit -= buf.len();
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Debug for BytesWriter<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BytesWriter").finish()
    }
}

//# Impls

impl ToBytes for [u8] {
    type Error = std::io::Error;
    fn to_bytes(&self, stream: &mut BytesWriter) -> Result<(), Self::Error> {
        stream.write_all(self)
    }
}

impl ToBytes for Vec<u8> {
    type Error = std::io::Error;
    fn to_bytes(&self, stream: &mut BytesWriter) -> Result<(), Self::Error> {
        stream.write_all(self)
    }
}

impl ToBytes for IpAddr {
    type Error = std::io::Error;
    fn to_bytes(&self, stream: &mut BytesWriter) -> Result<(), Self::Error> {
        match self {
            Self::V4(v4) => v4.to_bytes(stream),
            Self::V6(v6) => v6.to_bytes(stream),
        }
    }
}

impl ToBytes for Ipv4Addr {
    type Error = std::io::Error;
    fn to_bytes(&self, bytestream: &mut BytesWriter) -> Result<(), Self::Error> {
        bytestream.write_all(&self.octets())
    }
}

impl ToBytes for Ipv6Addr {
    type Error = std::io::Error;
    fn to_bytes(&self, bytestream: &mut BytesWriter) -> Result<(), Self::Error> {
        bytestream.write_all(&self.octets())
    }
}

#[cfg(test)]
mod tests {
    use std::{io::ErrorKind, usize};

    use byteorder::{WriteBytesExt, BE};

    use super::*;

    #[test]
    fn buf_write() {
        let mut buf = BytesMut::new();
        let mut br = BytesWriter::new(&mut buf, usize::MAX);
        br.put_u32(0x01020304);
        br.put_u8(0x05);

        drop(br);
        assert_eq!(buf[..], [1, 2, 3, 4, 5])
    }

    #[test]
    fn io_write() -> io::Result<()> {
        let mut buf = BytesMut::new();
        let mut br = BytesWriter::new(&mut buf, usize::MAX);
        br.write_u32::<BE>(0x01020304)?;
        br.write_u8(0x05)?;

        drop(br);
        assert_eq!(buf[..], [1, 2, 3, 4, 5]);
        Ok(())
    }

    #[test]
    fn limit_on_main_writer() -> io::Result<()> {
        let mut buf = BytesMut::new();
        let mut br = BytesWriter::new(&mut buf, 10);
        br.write_u32::<BE>(0x01020304)?;
        br.write_u32::<BE>(0x05060708)?;

        assert_eq!(br.bytes.as_mut()[..], [1, 2, 3, 4, 5, 6, 7, 8]);

        assert_eq!(
            br.write_u32::<BE>(0xffffffff).unwrap_err().kind(),
            ErrorKind::WriteZero
        );

        drop(br);
        assert_eq!(buf[..], [1, 2, 3, 4, 5, 6, 7, 8]);

        Ok(())
    }

    #[test]
    fn limit_on_marker_writer() -> io::Result<()> {
        let mut buf = BytesMut::new();
        let mut br = BytesWriter::new(&mut buf, 100);
        br.write_u32::<BE>(0x01020304)?;
        let marker = br.marker::<u32>();

        br.write_u32::<BE>(0x05060708)?;

        let mut slice = br.apply(marker);

        slice.write_u32::<BE>(0xffffffff)?;
        assert_eq!(
            slice.write_u32::<BE>(2).unwrap_err().kind(),
            ErrorKind::WriteZero
        );

        drop(br);
        assert_eq!(buf[..], [1, 2, 3, 4, 0xff, 0xff, 0xff, 0xff, 5, 6, 7, 8]);

        Ok(())
    }

    #[test]
    fn marker_without_realloc() {
        let mut buf = BytesMut::with_capacity(32);
        let mut writer = BytesWriter {
            limit: usize::MAX,
            markers: 0,
            bytes: &mut buf,
        };
        writer.put_u16(0xffff);

        let marker = writer.marker::<u16>();

        writer.put_u16(1);
        writer.put_u16(2);
        writer.put_u16(3);

        let n = writer.bytes_written_since(&marker);
        assert_eq!(n, 6);

        writer.apply(marker).write_u16::<BE>(n as u16).unwrap();

        drop(writer);
        assert_eq!(
            buf[..],
            [0xff, 0xff, 0x00, 0x06, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03]
        )
    }

    #[test]
    fn marker_with_realloc() {
        let mut buf = BytesMut::with_capacity(6);
        let mut writer = BytesWriter {
            limit: usize::MAX,
            markers: 0,
            bytes: &mut buf,
        };
        writer.put_u16(0xffff);

        let marker = writer.marker::<u16>();

        writer.put_u16(1);
        writer.put_u16(2);
        writer.put_u16(3);

        let n = writer.bytes_written_since(&marker);
        assert_eq!(n, 6);

        writer.apply(marker).write_u16::<BE>(n as u16).unwrap();

        drop(writer);
        assert_eq!(
            buf[..],
            [0xff, 0xff, 0x00, 0x06, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03]
        )
    }
}
