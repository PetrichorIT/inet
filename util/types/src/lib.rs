#![warn(clippy::pedantic)]
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::module_name_repetitions
)]

use bytes_io::FromBytes;

pub mod arp;
pub mod icmpv4;
pub mod icmpv6;
pub mod iface;
pub mod ip;
pub mod tcp;
pub mod udp;
pub mod util;

#[must_use]
pub fn split_off_front(mut buf: Vec<u8>, pos: usize) -> Vec<u8> {
    buf.copy_within(pos.., 0);
    buf.truncate(buf.len() - pos);
    buf
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TransportLayerHeader {
    pub src: u16,
    pub dst: u16,
}

impl FromBytes for TransportLayerHeader {
    type Error = std::io::Error;
    fn from_bytes(stream: &mut bytes_io::BytesReader) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        Ok(TransportLayerHeader {
            src: stream.get_u16(),
            dst: stream.get_u16(),
        })
    }
}
