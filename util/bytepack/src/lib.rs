#![deny(unused_must_use)]
#![warn(clippy::pedantic)]
#![warn(missing_docs, missing_debug_implementations, unreachable_pub)]
#![allow(clippy::needless_doctest_main, clippy::module_name_repetitions)]
#![deny(unsafe_code)]
//! Provides tools for parsing and packing bytestreams.
//!
//! The `bytepack` crate provides intuitive tools to assemble and parse
//! bytestreams, based on abitrary serializable types.
//!

use std::{
    io::{self, Read, Write},
    mem,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

#[cfg(test)]
mod tests;

pub use byteorder::*;

/// A trait that allows types to be converted into bytestreams.
///
/// Any type that implementes `ToBytestream` can be converrted or appened to
/// a bytestream representation of itself. If the type also implements
/// `FromBytestream`, it is expected that `FromBytestream::from_bytestream` acts as the
/// inverse operation to `ToBytestream::to_bytestream`.
pub trait ToBytestream {
    /// The type of errors that can occur during serialization.
    type Error;

    /// Appends a serialized representation of `self` to a bytestream writer.
    ///
    /// This function is used to serialize `self` into its bytestream representation.
    /// Use the provided `BytestreamWriter` to write the data to an abitrary
    /// output.
    ///
    /// # Errors
    ///
    /// This function can return errors, if either the writer cannot support the
    /// returned bytestream, or some parsing invariant does not hold.
    fn to_bytestream(&self, stream: &mut BytestreamWriter) -> Result<(), Self::Error>;

    /// Serializes `self` into a standalone bytevector.
    ///
    /// # Errors
    ///
    /// See `ToBytestream::to_bytestream`.
    fn to_vec(&self) -> Result<Vec<u8>, Self::Error> {
        let mut vec = Vec::new();
        let mut stream = BytestreamWriter { buf: &mut vec };
        self.to_bytestream(&mut stream)?;
        Ok(vec)
    }

    /// Serializes `self`, appending the bytestream to a vector.
    ///
    /// # Errors
    ///
    /// See `ToBytestream::to_bytestream`.
    /// If this operation fails, some bytes of the provided `buf` may have allready been edited.
    fn append_to_vec(&self, buf: &mut Vec<u8>) -> Result<(), Self::Error> {
        let mut stream = BytestreamWriter { buf };
        self.to_bytestream(&mut stream)?;
        Ok(())
    }
}

/// A writeable bytestream abstraction.
///
/// This type can be used to write a continous bytestream
/// using `std::io::Write`, but this type also provides
/// non-end-of-stream updates, using `Marker`.
#[derive(Debug)]
pub struct BytestreamWriter<'a> {
    buf: &'a mut Vec<u8>,
}

/// A allready written subslice of a `BytestreamWriter`, that
/// can be used override previous values on the bytestream.
#[derive(Debug)]
pub struct Marker {
    pos: usize,
    len: usize,
}

impl BytestreamWriter<'_> {
    /// Indicates if the outputstream is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The length of the underlying buffer.
    #[must_use]
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// Reserves at least `additional` many bytes in the underlying buffer.
    pub fn reserve(&mut self, additional: usize) {
        self.buf.reserve(additional);
    }

    /// Allocates and writes a `Marker` on the bytestream of the given `len`.
    ///
    /// # Errors
    ///
    /// May fail, if the bytestream cannot hold `len` more bytes.
    pub fn create_maker(&mut self, len: usize) -> io::Result<Marker> {
        let pos = self.buf.len();
        self.write_all(&vec![0; len])?;
        Ok(Marker { pos, len })
    }

    /// Allocates and writes a new `Marker`, using the size of the type `T`
    /// as a length indication.
    ///
    /// # Errors
    ///
    /// May fail, if the bytestream cannot hold `size_of::<T>()` more bytes.
    pub fn create_typed_marker<T>(&mut self) -> io::Result<Marker> {
        self.create_maker(mem::size_of::<T>())
    }

    /// Grants access to the subslice, referenced by the marker
    /// to update the value.
    ///
    /// Note that only the marked subslice is available, so
    /// writes to this subslice cannot depend on any other
    /// datapoints.
    pub fn update_marker(&mut self, marker: &Marker) -> &mut [u8] {
        &mut self.buf[marker.pos..(marker.pos + marker.len)]
    }

    /// Messures the number of bytes written since the creation of the marker.
    /// This returns the number of bytes *after* the end of the marker.
    ///
    /// # Panics
    ///
    /// May panic if the marker does not belong to this bytestream.
    pub fn len_since_marker(&mut self, marker: &Marker) -> usize {
        let pos = self.buf.len();
        if let Some(len) = pos.checked_sub(marker.pos + marker.len) {
            len
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

/// A trait that allows a type to be deserialized from a bytestream.
///
/// Any type that implementes `FromBytestream` can be converrted or appened to
/// a bytestream representation of itself. If the type also implements
/// `ToBytestream`, it is expected that `ToBytestream::to_bytestream` acts as the
/// inverse operation to `FromBytestream::from_bytestream`.
pub trait FromBytestream: Sized {
    /// The type of errors that can occur during deserialization.
    type Error;

    /// Parses an instance of `Self` from a given bytestream, returning an error
    /// of this operation fails.
    ///
    /// This parsing function must not fully consume the readers bytestream,
    /// but might, dependent on the type.
    ///
    /// # Errors
    ///
    /// May return custom errors, if the parsing fails.
    fn from_bytestream(stream: &mut BytestreamReader) -> Result<Self, Self::Error>;

    /// Parses an instance of `Self` from a slice, consuming the slice.
    /// This function does not indicate how many bytes were read from the slice.
    ///
    /// # Errors
    ///
    /// See `FromBytestream::from_bytestream`.
    fn from_slice(slice: &[u8]) -> Result<Self, Self::Error> {
        let mut reader = BytestreamReader { offset: 0, slice };
        Self::from_bytestream(&mut reader)
    }

    /// Parses an instance `Self` from a slice, mutating the slice to
    /// represent the non-yet-consumed bytes after success.
    ///
    /// # Errors
    ///
    /// See `FromBytestream::from_bytestream`.
    /// Note that the slice only mutates, if the parsing succeeds.
    /// On error, the slice remains unedited.
    fn read_from_slice(slice: &mut &[u8]) -> Result<Self, Self::Error> {
        let mut reader = BytestreamReader { offset: 0, slice };
        let object = Self::from_bytestream(&mut reader)?;
        *slice = reader.remaining();
        Ok(object)
    }

    /// Parses an instance of `Self` from a vector, consuming all read bytes.
    ///
    /// # Errors
    ///
    /// See `FromBytestream::from_bytestream`.
    fn read_from_vec(vec: &mut Vec<u8>) -> Result<Self, Self::Error> {
        let mut reader = BytestreamReader {
            offset: 0,
            slice: vec,
        };
        let len = reader.remaining().len();
        let object = Self::from_bytestream(&mut reader)?;
        let consumed = len - reader.remaining().len();
        vec.drain(..consumed);
        Ok(object)
    }
}

/// A readable bytestream, with substream abstractions.
///
/// Values can be read using `std::io::Read` in combination with
/// `byteorder::ReadBytesExt`.
#[derive(Debug)]
pub struct BytestreamReader<'a> {
    offset: usize,
    slice: &'a [u8],
}

impl<'a> BytestreamReader<'a> {
    #[inline]
    fn remaining(&self) -> &'a [u8] {
        &self.slice[self.offset..]
    }

    /// Tries to extract a substream of length `n`.
    ///
    /// # Errors
    ///
    /// This function fails, if less that `n` bytes remain in the bytestream.
    pub fn extract(&mut self, n: usize) -> io::Result<BytestreamReader<'_>> {
        if self.remaining().len() < n {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "invalid substream length",
            ));
        }
        let stream = BytestreamReader {
            offset: 0,
            slice: &self.remaining()[..n],
        };
        self.offset += n;
        Ok(stream)
    }

    /// Moves back into already read data
    ///
    /// # Panics
    ///
    /// Panics if the current position if smaller than n.
    pub fn bump_back(&mut self, n: usize) {
        assert!(self.offset >= n, "cannot bumb beyond the start point");
        self.offset -= n;
    }

    /// Indicates whether a bytestream is full consumed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.remaining().is_empty()
    }
}

impl Read for BytestreamReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let min = buf.len().min(self.remaining().len());
        buf[..min].copy_from_slice(&self.remaining()[..min]);
        self.offset += min;
        Ok(min)
    }
}

/// An macro to automatically implement `ToBytestream` and `FromBytestream`
/// for primitive enumerations with `#[repr(ux)]`
#[macro_export]
macro_rules! raw_enum {
    ($(#[$outer:meta])*
    $vis: vis enum $ident: ident {
        type Repr = $repr:ty where $order:ty;
        $(
            $(#[$inner:meta])*
            $variant:ident = $prim:literal,
        )+
    }) => {
        $(#[$outer])*
        #[repr($repr)]
        $vis enum $ident {
            $(
                $(#[$inner])*
                $variant = $prim,
            )+
        }

        impl ::std::str::FromStr for $ident {
            type Err = ::std::io::Error;
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                match s {
                    $(
                        stringify!($variant) => Ok(Self::$variant),
                    )+
                    _ => Err(::std::io::Error::new(
                        ::std::io::ErrorKind::InvalidInput,
                        "unknown string: ".to_string() + s
                    ))
                }
            }
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

macro_rules! impl_number {
    ($($t:ty, $fn_read:ident, $fn_write:ident);+) => {
        $(
            impl FromBytestream for $t {
                type Error = std::io::Error;
                fn from_bytestream(bytestream: &mut BytestreamReader) -> Result<Self, Self::Error> {
                    bytestream.$fn_read::<BE>()
                }
            }
        )*
        $(
            impl ToBytestream for $t {
                type Error = std::io::Error;
                fn to_bytestream(&self, bytestream: &mut BytestreamWriter) -> Result<(), Self::Error> {
                    bytestream.$fn_write::<BE>(*self)
                }
            }
        )*
    };
}

impl_number!(
    u16, read_u16, write_u16;
    u32, read_u32, write_u32;
    u64, read_u64, write_u64;
    u128, read_u128, write_u128;
    i16, read_i16, write_i16;
    i32, read_i32, write_i32;
    i64, read_i64, write_i64;
    i128, read_i128, write_i128
);

impl ToBytestream for [u8] {
    type Error = std::io::Error;
    fn to_bytestream(&self, stream: &mut BytestreamWriter) -> Result<(), Self::Error> {
        stream.write_all(self)
    }
}

impl ToBytestream for Vec<u8> {
    type Error = std::io::Error;
    fn to_bytestream(&self, stream: &mut BytestreamWriter) -> Result<(), Self::Error> {
        stream.write_all(self)
    }
}

impl ToBytestream for IpAddr {
    type Error = std::io::Error;
    fn to_bytestream(&self, stream: &mut BytestreamWriter) -> Result<(), Self::Error> {
        match self {
            Self::V4(v4) => v4.to_bytestream(stream),
            Self::V6(v6) => v6.to_bytestream(stream),
        }
    }
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

impl ToBytestream for Ipv6Addr {
    type Error = std::io::Error;
    fn to_bytestream(&self, bytestream: &mut BytestreamWriter) -> Result<(), Self::Error> {
        bytestream.write_all(&self.octets())
    }
}

impl FromBytestream for Ipv6Addr {
    type Error = std::io::Error;
    fn from_bytestream(bytestream: &mut BytestreamReader) -> Result<Self, Self::Error> {
        Ok(Ipv6Addr::from(bytestream.read_u128::<BE>()?))
    }
}
