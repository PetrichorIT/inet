use std::{
    io::{self, Read, Write},
    marker::PhantomData,
    net::Ipv4Addr,
};

pub use bytestream::{ByteOrder, StreamReader, StreamWriter};

/// This trait allows types to be converted into bytestreams
/// using custom implmentations.
pub trait ToBytestream {
    /// An error type that may occur, when converting self to a bytestream.
    type Error;
    /// Appends self to the provided bytestream.
    fn to_bytestream(&self, stream: &mut BytestreamWriter) -> Result<(), Self::Error>;
    /// Appends self to a new bytestream, retuned as a bytevector in the end.
    fn to_buffer(&self) -> Result<Vec<u8>, Self::Error> {
        let mut stream = BytestreamWriter { buf: Vec::new() };
        self.to_bytestream(&mut stream)?;
        Ok(stream.buf)
    }

    fn to_buffer_with(&self, buf: Vec<u8>) -> Result<Vec<u8>, Self::Error> {
        let mut stream = BytestreamWriter { buf };
        self.to_bytestream(&mut stream)?;
        Ok(stream.buf)
    }
}

#[derive(Debug)]
pub struct BytestreamWriter {
    buf: Vec<u8>,
}

pub struct PositionMarker<T> {
    pos: usize,
    len: usize,
    order: ByteOrder,
    _phantom: PhantomData<T>,
}

impl BytestreamWriter {
    pub fn add_marker<T: StreamWriter>(
        &mut self,
        value: T,
        order: ByteOrder,
    ) -> io::Result<PositionMarker<T>> {
        let pos = self.buf.len();
        value.write_to(self, order)?;
        let len = self.buf.len() - pos;
        Ok(PositionMarker {
            pos,
            order,
            len,
            _phantom: PhantomData,
        })
    }

    pub fn write_to_marker<T: StreamWriter>(
        &mut self,
        marker: PositionMarker<T>,
        value: T,
    ) -> io::Result<()> {
        let mut slice = &mut self.buf[marker.pos..(marker.pos + marker.len)];
        value.write_to(&mut slice, marker.order)
    }

    pub fn len_since<T>(&self, marker: &PositionMarker<T>) -> io::Result<usize> {
        let pos = self.buf.len();
        if let Some(len) = pos.checked_sub(marker.pos + marker.len) {
            return Ok(len);
        } else {
            todo!()
        }
    }
}

impl Write for BytestreamWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.buf.write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.buf.flush()
    }
}

pub trait FromBytestream: Sized {
    type Error;
    fn from_bytestream(stream: &mut BytestreamReader) -> Result<Self, Self::Error>;

    fn from_slice(slice: &[u8]) -> Result<Self, Self::Error> {
        let mut reader = BytestreamReader { slice };
        Self::from_bytestream(&mut reader)
    }

    fn read_from_slice(slice: &mut &[u8]) -> Result<Self, Self::Error> {
        let mut reader = BytestreamReader { slice };
        let object = Self::from_bytestream(&mut reader)?;
        *slice = reader.slice;
        Ok(object)
    }

    fn read_from_vec(vec: &mut Vec<u8>) -> Result<Self, Self::Error> {
        let mut reader = BytestreamReader { slice: &vec };
        let len = reader.slice.len();
        let object = Self::from_bytestream(&mut reader)?;
        let consumed = len - reader.slice.len();
        vec.drain(..consumed);
        Ok(object)
    }
}

#[derive(Debug)]
pub struct BytestreamReader<'a> {
    slice: &'a [u8],
}

impl BytestreamReader<'_> {
    pub fn extract(&mut self, n: usize) -> io::Result<BytestreamReader<'_>> {
        if self.slice.len() < n {
            dbg!(self.slice.len(), n);
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "invalid substream length",
            ));
        }
        let stream = BytestreamReader {
            slice: &self.slice[..n],
        };
        self.slice = &self.slice[n..];
        Ok(stream)
    }

    pub fn is_empty(&self) -> bool {
        self.slice.is_empty()
    }
}

impl Read for BytestreamReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let min = buf.len().min(self.slice.len());
        buf[..min].copy_from_slice(&self.slice[..min]);
        self.slice = &self.slice[min..];
        Ok(min)
    }
}

#[macro_export]
macro_rules! raw_enum {
    (
        $(#[$outer:meta])*
        $vis: vis enum $ident: ident {
            type Repr = $repr:ty where $order:expr;
            $(
                $variant:tt = $prim:literal,
            )+
        }
    ) => {
        $(#[$outer])*
        #[repr($repr)]
        $vis enum $ident {
            $(
                $variant = $prim,
            )+
        }

        impl ::bytepack::ToBytestream for $ident {
            type Error = ::std::io::Error;
            fn to_bytestream(&self, stream: &mut ::bytepack::BytestreamWriter)
                -> ::std::result::Result<(), Self::Error> {
                    use ::bytepack::StreamWriter;
                    (*self as $repr).write_to(stream, $order)
            }
        }

        impl ::bytepack::FromBytestream for $ident {
            type Error = ::std::io::Error;
            fn from_bytestream(stream: &mut ::bytepack::BytestreamReader)
                -> ::std::result::Result<Self, Self::Error> {
                    use ::bytepack::StreamReader;
                    let value = <$repr>::read_from(stream, $order)?;
                    match value {
                        $(
                            $prim => Ok(Self::$variant),
                        )+
                        _ => Err(::std::io::Error::new(
                            ::std::io::ErrorKind::InvalidInput,
                            "unknown discriminant"
                        ))
                    }
            }
        }
    };
}

impl ToBytestream for Ipv4Addr {
    type Error = std::io::Error;
    fn to_bytestream(&self, bytestream: &mut BytestreamWriter) -> Result<(), Self::Error> {
        bytestream.write_all(&self.octets())
    }
}

impl FromBytestream for Ipv4Addr {
    type Error = std::io::Error;
    fn from_bytestream(bytestream: &mut BytestreamReader) -> Result<Self, Self::Error> {
        Ok(Ipv4Addr::from(u32::read_from(
            bytestream,
            ByteOrder::BigEndian,
        )?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ::byteorder::{WriteBytesExt, BE};
    use bytestream::StreamReader;
    use std::io::Error;

    #[test]
    fn a() {
        #[derive(Debug)]
        struct A {
            vals: Vec<u16>,
            trail: u64,
        }
        impl ToBytestream for A {
            type Error = Error;
            fn to_bytestream(&self, stream: &mut BytestreamWriter) -> Result<(), Self::Error> {
                let marker = stream.add_marker(0u16, ByteOrder::BigEndian)?;
                for val in &self.vals {
                    stream.write_u16::<BE>(*val)?;
                }
                let len = stream.len_since(&marker)?;
                stream.write_to_marker(marker, len as u16)?;
                self.trail.write_to(stream, ByteOrder::BigEndian)?;
                Ok(())
            }
        }

        impl FromBytestream for A {
            type Error = Error;
            fn from_bytestream(stream: &mut BytestreamReader) -> Result<Self, Self::Error> {
                let len = u16::read_from(stream, ByteOrder::BigEndian)?;
                let mut substr = stream.extract(len as usize)?;
                let mut vals = Vec::new();
                while !substr.is_empty() {
                    vals.push(u16::read_from(&mut substr, ByteOrder::BigEndian)?);
                }
                let trail = u64::read_from(stream, ByteOrder::BigEndian)?;

                Ok(Self { vals, trail })
            }
        }

        let a = A {
            vals: vec![1, 2, 3, 4],
            trail: u64::MAX,
        };
        let mut buf = a.to_buffer().unwrap();
        let new = A::read_from_vec(&mut buf);

        println!("{:?}", a);
        println!("{:?}", buf);
        println!("{:?}", new);
    }

    #[test]
    fn from_mut_slice() {
        #[derive(Debug, PartialEq, Eq)]
        struct AB {
            a: u32,
            b: u32,
        }
        impl FromBytestream for AB {
            type Error = std::io::Error;
            fn from_bytestream(stream: &mut BytestreamReader) -> Result<Self, Self::Error> {
                Ok(Self {
                    a: u32::read_from(stream, ByteOrder::BigEndian)?,
                    b: u32::read_from(stream, ByteOrder::BigEndian)?,
                })
            }
        }

        let buf = [0, 0, 0, 0, 255, 255, 255, 255, 0, 1, 2, 3];
        let mut slice = &buf[..];
        let ab = AB::read_from_slice(&mut slice).unwrap();
        assert_eq!(ab, AB { a: 0, b: u32::MAX });
        assert_eq!(slice, [0, 1, 2, 3]);
    }
}
