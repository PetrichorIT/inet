//! The Domain-Name-Server Protocol (DNS)

mod resolver;
pub use resolver::DnsResolver;
pub use resolver::ToSocketAddrs;
pub(crate) use resolver::default_dns_resolve;
pub use resolver::sim_internal_dns_resolve;

mod api;
pub use api::lookup_host;
pub use api::set_dns_resolver;
