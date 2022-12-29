use std::io::{Cursor, Write};

pub(crate) fn split_off_front(mut buf: Vec<u8>, pos: usize) -> Vec<u8> {
    for i in pos..buf.len() {
        buf[i - pos] = buf[i]
    }
    buf.truncate(buf.len() - pos);
    buf
}

/// The `IntoBytestream` trait allows the conversion of an object into a bytestream
/// attached to a byte-oriented sink.
pub trait IntoBytestream {
    /// The Error type that can occur in translating the object.
    type Error;

    /// Attaches the bytestream respresentation of self to the provided bytestream.
    fn into_bytestream(&self, bytestream: &mut impl Write) -> Result<(), Self::Error>;

    /// Attaches the bytestream respresentation of self to an empty bytestream.
    fn into_buffer(&self) -> Result<Vec<u8>, Self::Error> {
        let mut buffer = Vec::new();
        self.into_bytestream(&mut buffer)?;
        Ok(buffer)
    }
}

/// The `FromBytestream` trait allows for the construction of Self from a bytestream
/// of a source.
pub trait FromBytestream: Sized {
    /// The Error type that can occur in constructing the object.
    type Error;

    /// Constructs a instance of Self from the given bytestream, advancing
    /// the stream in the process.
    fn from_bytestream(bytestream: &mut Cursor<impl AsRef<[u8]>>) -> Result<Self, Self::Error>;

    /// Constructs a instance of Self from the given buffer, consuming
    /// the stream in the process.
    fn from_buffer(buffer: impl AsRef<[u8]>) -> Result<Self, Self::Error> {
        let mut cursor = Cursor::new(buffer);
        Self::from_bytestream(&mut cursor)
    }
}

// pub struct Array<T, const N: usize> {
//     array: [Option<T>; N],
//     len: usize,
// }

// impl<T, const N: usize> Array<T, N> {
//     const INIT: Option<T> = None;
//     pub const fn new() -> Self {
//         Self {
//             array: [Self::INIT; N],
//             len: 0,
//         }
//     }

//     pub fn truncate(&mut self, len: usize) {
//         assert!(len < N);
//         if len > self.len {
//             return;
//         }
//         for i in len..self.len {
//             self.array[i] = None;
//         }
//         self.len = len;
//     }

//     pub fn len(&self) -> usize {
//         self.len
//     }

//     pub fn is_empty(&self) -> bool {
//         self.len == 0
//     }

//     pub fn as_slice(&self) -> &[T] {
//         self.array.as_slice().map(|v| v.as_ref().unwrap())
//     }
// }
