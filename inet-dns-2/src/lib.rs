//! DNS resolvers
//!
//! # General structure
//!
//! Zonefile -> Raw unordered list of RRs
//! RecordMap -> List of RRs belonging to one class (e.g. IN); manages timeouts on local entries
//! ZoneResolver -> Wrapper round RM, to manage all requests to a zone -> local queries
//! *Nameserver -> Manager of multiple zones, dispatching queries, managing caching
//! UdpBased -> Impl of Connection over a dyn DnsNameserver

pub mod client;
pub mod core;
pub mod server;
