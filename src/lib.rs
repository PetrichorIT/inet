#![feature(type_alias_impl_trait)]

mod common;
pub use common::*;
#[macro_use]
mod macros;

pub mod dhcp;
pub mod dns;
pub mod ip;
pub mod udp;
