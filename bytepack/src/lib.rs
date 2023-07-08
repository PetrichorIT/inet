use std::{
    io::{self, Read, Write},
    mem,
    net::Ipv4Addr,
};

pub use byteorder::*;

/// This trait allows types to be converted into bytestreams
/// using custom implmentations.
pub trait ToBytestream {
    /// An error type that may occur, when converting self to a bytestream.
    type Error;
    /// Appends self to the provided bytestream.
    fn to_bytestream(&self, stream: &mut BytestreamWriter) -> Result<(), Self::Error>;

    /// Appends self to a new bytestream, retuned as a bytevector in the end.
    fn to_vec(&self) -> Result<Vec<u8>, Self::Error> {
        let mut vec = Vec::new();
        let mut stream = BytestreamWriter { buf: &mut vec };
        self.to_bytestream(&mut stream)?;
        Ok(vec)
    }

    fn append_to_vec(&self, buf: &mut Vec<u8>) -> Result<(), Self::Error> {
        let mut stream = BytestreamWriter { buf };
        self.to_bytestream(&mut stream)?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct BytestreamWriter<'a> {
    buf: &'a mut Vec<u8>,
}

#[derive(Debug)]
pub struct Marker {
    pos: usize,
    len: usize,
}

impl BytestreamWriter<'_> {
    pub fn create_maker(&mut self, len: usize) -> io::Result<Marker> {
        let pos = self.buf.len();
        self.write_all(&vec![0; len])?;
        Ok(Marker { pos, len })
    }

    pub fn create_typed_marker<T>(&mut self) -> io::Result<Marker> {
        self.create_maker(mem::size_of::<T>())
    }

    pub fn update_marker(&mut self, marker: &Marker) -> &mut [u8] {
        &mut self.buf[marker.pos..(marker.pos + marker.len)]
    }

    pub fn len_since_marker(&mut self, marker: &Marker) -> usize {
        let pos = self.buf.len();
        if let Some(len) = pos.checked_sub(marker.pos + marker.len) {
            return len;
        } else {
            todo!()
        }
    }
}

impl Write for BytestreamWriter<'_> {
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
    ($(#[$outer:meta])*
    $vis: vis enum $ident: ident {
        type Repr = $repr:ty where $order:ty;
        $(
            $variant:tt = $prim:literal,
        )+
    }) => {
        $(#[$outer])*
        #[repr($repr)]
        $vis enum $ident {
            $(
                $variant = $prim,
            )+
        }

        impl $ident {
            $vis fn from_raw_repr(repr: $repr) -> ::std::io::Result<Self> {
                match repr {
                    $(
                        $prim => Ok(Self::$variant),
                    )+
                    _ => Err(::std::io::Error::new(
                        ::std::io::ErrorKind::InvalidInput,
                        "unknown discriminant"
                    ))
                }
            }

            $vis fn to_raw_repr(&self) -> $repr {
                *self as $repr
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
        Ok(Ipv4Addr::from(bytestream.read_u32::<BE>()?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ::byteorder::{ReadBytesExt, WriteBytesExt, BE};
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
                let marker = stream.create_typed_marker::<u16>()?;
                for val in &self.vals {
                    stream.write_u16::<BE>(*val)?;
                }
                let len = stream.len_since_marker(&marker) as u16;
                stream.update_marker(&marker).write_u16::<BE>(len)?;
                stream.write_u64::<BE>(self.trail)?;
                Ok(())
            }
        }

        impl FromBytestream for A {
            type Error = Error;
            fn from_bytestream(stream: &mut BytestreamReader) -> Result<Self, Self::Error> {
                let len = stream.read_u16::<BE>()?;
                let mut substr = stream.extract(len as usize)?;
                let mut vals = Vec::new();
                while !substr.is_empty() {
                    vals.push(substr.read_u16::<BE>()?);
                }
                let trail = stream.read_u64::<BE>()?;

                Ok(Self { vals, trail })
            }
        }

        let a = A {
            vals: vec![1, 2, 3, 4],
            trail: u64::MAX,
        };
        let mut buf = a.to_vec().unwrap();
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
                    a: stream.read_u32::<BE>()?,
                    b: stream.read_u32::<BE>()?,
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
