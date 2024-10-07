#![deny(unused_must_use)]
#![warn(clippy::pedantic)]
#![warn(missing_docs, missing_debug_implementations, unreachable_pub)]
#![allow(clippy::module_name_repetitions)]
//! Implementation of the PCAPNG file format

mod blocks;
mod linktype;
mod reader;
mod writer;

#[cfg(feature = "test-util")]
mod test_util;

#[cfg(test)]
mod tests;

pub use blocks::*;
pub use linktype::Linktype;
pub use reader::BlockReader;
pub use writer::{BlockWriter, DefaultBlockWriter};

#[cfg(feature = "test-util")]
pub use test_util::TestBlockWriter;

type MacAddress = [u8; 6];
