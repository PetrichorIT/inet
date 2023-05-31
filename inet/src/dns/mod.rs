//! The Domain-Name-Server Protocol (DNS)

mod resolver;
pub use resolver::lookup_host;
pub use resolver::ToSocketAddrs;

cfg_dns! {
    mod nameserver;
    pub use nameserver::*;

    mod zonefile;
    pub use zonefile::DNSZoneFile;
}
