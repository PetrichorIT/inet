//! Traits, helpers, and type definitions for asynchronous I/O functionality
//!
//! This module contains the some helpers for internal types, that are usually found
//! in `tokio::io` but only with the feature `net` enabled. Since the
//! tokio-des-inet stack should not make use of this feature, these implementations
//! replace the tokio-interal ones.

mod ready;
pub use ready::*;

mod interest;
pub use interest::*;
