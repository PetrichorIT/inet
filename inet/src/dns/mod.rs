//! The Domain-Name-Server Protocol (DNS)

mod resolver;
pub(crate) use resolver::default_dns_resolve;
pub use resolver::DnsResolver;
pub use resolver::ToSocketAddrs;

mod api;
pub use api::lookup_host;
pub use api::set_dns_resolver;
