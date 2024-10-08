#![warn(clippy::pedantic)]
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::module_name_repetitions
)]

#[macro_use]
mod macros;

pub mod arp;
pub mod icmpv4;
pub mod icmpv6;
pub mod iface;
pub mod ip;
pub mod routing;
pub mod tcp;
pub mod udp;
pub mod util;

#[cfg(feature = "uds")]
pub mod uds;

#[must_use]
pub fn split_off_front(mut buf: Vec<u8>, pos: usize) -> Vec<u8> {
    buf.copy_within(pos.., 0);
    buf.truncate(buf.len() - pos);
    buf
}
