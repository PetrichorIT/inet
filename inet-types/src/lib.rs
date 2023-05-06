#![warn(clippy::pedantic)]
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::module_name_repetitions
)]

use std::io::{Cursor, Write};

#[macro_use]
mod macros;

pub mod arp;
pub mod dns;
pub mod icmp;
pub mod iface;
pub mod ip;
pub mod tcp;
pub mod udp;
pub mod uds;

#[must_use]
pub fn split_off_front(mut buf: Vec<u8>, pos: usize) -> Vec<u8> {
    for i in pos..buf.len() {
        buf[i - pos] = buf[i];
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
    ///
    /// # Errors
    ///
    /// May return an error if writing has failed, either due to an error
    /// in parsing, or a limit of the targeted container.
    ///
    fn to_bytestream(&self, bytestream: &mut impl Write) -> Result<(), Self::Error>;

    /// Attaches the bytestream respresentation of self to an empty bytestream.
    ///
    /// # Errors
    ///
    /// May return an error if the writing has failed.
    ///
    fn to_buffer(&self) -> Result<Vec<u8>, Self::Error> {
        let mut buffer = Vec::new();
        self.to_bytestream(&mut buffer)?;
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
    ///
    /// # Errors
    ///
    /// May return an error related to invalid data from the provided
    /// reader.
    ///
    fn from_bytestream(bytestream: &mut Cursor<impl AsRef<[u8]>>) -> Result<Self, Self::Error>;

    /// Constructs a instance of Self from the given buffer, consuming
    /// the stream in the process.
    ///
    /// # Errors
    ///
    /// May return an error related to invalid data from the provided
    /// buffer.
    ///
    fn from_buffer(buffer: impl AsRef<[u8]>) -> Result<Self, Self::Error> {
        let mut cursor = Cursor::new(buffer);
        Self::from_bytestream(&mut cursor)
    }
}
