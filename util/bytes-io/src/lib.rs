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

mod read;
mod write;

pub use self::read::*;
pub use self::write::*;
