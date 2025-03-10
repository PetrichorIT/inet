use std::{
    io, mem,
    ops::{Deref, DerefMut},
};

use bytes::{buf::Limit, BufMut, BytesMut};

/// A
pub trait ToBytes {
    ///  A
    type Error;

    /// A
    fn to_bytestream(&self, writer: &mut BytesWriter) -> Result<(), Self::Error>;

    /// A
    fn write_to(&self, bytes: &mut BytesMut) -> Result<usize, Self::Error> {
        let mut writer = BytesWriter {
            limit: usize::MAX,
            markers: 0,
            bytes: bytes.split(),
        };
        self.to_bytestream(&mut writer)?;
        let n = writer.bytes.len();
        bytes.unsplit(writer.finish());
        Ok(n)
    }

    /// A
    fn to_bytes(&self) -> Result<BytesMut, Self::Error> {
        let mut bytes = BytesMut::new();
        self.write_to(&mut bytes)?;
        Ok(bytes)
    }
}

/// A
#[derive(Debug)]
pub struct BytesWriter {
    limit: usize,
    markers: usize,
    bytes: BytesMut,
}

/// A
#[derive(Debug)]
#[must_use]
pub struct Marker {
    pos: usize,
    bytes: Limit<BytesMut>,
}

impl BytesWriter {
    /// A
    pub fn new(limit: usize) -> Self {
        BytesWriter {
            limit,
            markers: 0,
            bytes: BytesMut::new(),
        }
    }

    /// A
    pub fn marker<T>(&mut self) -> Marker {
        let size = mem::size_of::<T>();
        let remaining = self.bytes.split_to(size).limit(size);
        self.markers += 1;
        Marker {
            pos: self.bytes.len(),
            bytes: remaining,
        }
    }

    /// A
    pub fn bytes_written_since(&self, marker: &Marker) -> usize {
        self.bytes.len() - marker.pos
    }

    /// A
    pub fn apply(&mut self, marker: Marker) {
        let mut bytes = marker.bytes.into_inner();
        mem::swap(&mut self.bytes, &mut bytes);
        self.bytes.unsplit(bytes);
        self.markers -= 1;
    }

    /// A
    pub fn finish(self) -> BytesMut {
        assert_eq!(
            self.markers, 0,
            "unapplied markers exist, bytestream not complete anymore"
        );
        self.bytes
    }
}

impl Deref for BytesWriter {
    type Target = dyn BufMut;
    fn deref(&self) -> &Self::Target {
        &self.bytes
    }
}

impl DerefMut for BytesWriter {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.bytes
    }
}

impl io::Write for BytesWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.len() > self.limit {
            return Err(io::Error::new(io::ErrorKind::WriteZero, "buffer overflow"));
        }
        self.bytes.extend_from_slice(&buf);
        self.limit -= buf.len();
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl io::Write for Marker {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.len() > self.bytes.remaining_mut() {
            return Err(io::Error::new(io::ErrorKind::WriteZero, "buffer overflow"));
        }
        self.bytes.put_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::{io::ErrorKind, usize};

    use byteorder::{WriteBytesExt, BE};

    use super::*;

    #[test]
    fn buf_write() {
        let mut br = BytesWriter::new(usize::MAX);
        br.put_u32(0x01020304);
        br.put_u8(0x05);

        assert_eq!(br.bytes[..], [1, 2, 3, 4, 5])
    }

    #[test]
    fn io_write() -> io::Result<()> {
        let mut br = BytesWriter::new(usize::MAX);
        br.write_u32::<BE>(0x01020304)?;
        br.write_u8(0x05)?;

        assert_eq!(br.bytes[..], [1, 2, 3, 4, 5]);
        Ok(())
    }

    #[test]
    fn limit_on_main_writer() -> io::Result<()> {
        let mut br = BytesWriter::new(10);
        br.write_u32::<BE>(0x01020304)?;
        br.write_u32::<BE>(0x05060708)?;

        assert_eq!(br.bytes[..], [1, 2, 3, 4, 5, 6, 7, 8]);

        assert_eq!(
            br.write_u32::<BE>(0xffffffff).unwrap_err().kind(),
            ErrorKind::WriteZero
        );

        assert_eq!(br.bytes[..], [1, 2, 3, 4, 5, 6, 7, 8]);

        Ok(())
    }

    #[test]
    fn limit_on_marker_writer() -> io::Result<()> {
        let mut br = BytesWriter::new(100);
        br.write_u32::<BE>(0x01020304)?;
        let mut marker = br.marker::<u32>();

        br.write_u32::<BE>(0x05060708)?;

        marker.write_u32::<BE>(0xffffffff)?;
        assert_eq!(
            marker.write_u32::<BE>(2).unwrap_err().kind(),
            ErrorKind::WriteZero
        );

        br.apply(marker);
        assert_eq!(
            &br.bytes[..],
            &[1, 2, 3, 4, 0xff, 0xff, 0xff, 0xff, 5, 6, 7, 8]
        );

        Ok(())
    }

    #[test]
    fn marker_without_realloc() {
        let mut writer = BytesWriter {
            limit: usize::MAX,
            markers: 0,
            bytes: BytesMut::with_capacity(32),
        };
        writer.put_u16(0xffff);

        let mut marker = writer.marker::<u16>();

        writer.put_u16(1);
        writer.put_u16(2);
        writer.put_u16(3);

        let n = writer.bytes_written_since(&marker);
        assert_eq!(n, 6);

        marker.write_u16::<BE>(n as u16).unwrap();

        writer.apply(marker);

        let buf = writer.bytes;
        assert_eq!(
            &buf[..],
            &[0xff, 0xff, 0x00, 0x06, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03]
        )
    }

    #[test]
    fn marker_with_realloc() {
        let mut writer = BytesWriter {
            limit: usize::MAX,
            markers: 0,
            bytes: BytesMut::with_capacity(6),
        };
        writer.put_u16(0xffff);

        let mut marker = writer.marker::<u16>();

        writer.put_u16(1);
        writer.put_u16(2);
        writer.put_u16(3);

        let n = writer.bytes_written_since(&marker);
        assert_eq!(n, 6);

        marker.write_u16::<BE>(n as u16).unwrap();

        writer.apply(marker);

        let buf = writer.bytes;
        assert_eq!(
            &buf[..],
            &[0xff, 0xff, 0x00, 0x06, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03]
        )
    }
}
