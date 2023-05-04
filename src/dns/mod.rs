//! Domain-Name-Server Protocol.

mod nameserver;
pub use nameserver::*;

mod resolver;
pub use resolver::lookup_host;
pub use resolver::ToSocketAddrs;

mod zonefile;
pub use zonefile::DNSZoneFile;
