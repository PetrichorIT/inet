//! Domain-Name-Server Protocol.

mod pkt;
pub use pkt::*;

mod nameserver;
pub use nameserver::*;

mod resolver;
pub use resolver::lookup_host;
pub use resolver::ToSocketAddrs;

mod common;
pub use common::*;

mod zonefile;
pub use zonefile::DNSZoneFile;

#[cfg(test)]
mod tests;
