use crate::ctx::IOContext;

use super::{resolver, DnsResolver};
use std::io::Result;
use std::net::SocketAddr;

/// Performs an address lookup with the bound resolver for this node.
///
/// By default, any `T` that can be trivialy converted into a `SocketAddr`
/// will be converted. If the input is however a name, the provided resolver
/// will preform the lookup.
///
/// The default resolver will not perform lookups on any names.
/// The resolver can be set using `set_dns_resolver`.
///
/// # Errors
///
/// This function fails, if called from outside of a node context,
/// or if the provided `host` cannot be resolved.
pub async fn lookup_host<T>(host: T) -> Result<impl Iterator<Item = SocketAddr>>
where
    T: resolver::ToSocketAddrs,
{
    resolver::lookup_host(host).await
}

/// Overrides the local dns resolver for the current node context.
///
/// This resolver will be used to lookup names, an can implement any arbitrary
/// operation to do so.
///
/// # Errors
///
/// This function fails, if called from outside of a node context.
pub fn set_dns_resolver(resolver: DnsResolver) -> Result<()> {
    IOContext::failable_api(|ctx| ctx.set_dns_resolver(resolver))
}

impl IOContext {
    fn set_dns_resolver(&mut self, resolver: DnsResolver) -> Result<()> {
        self.dns = resolver;
        Ok(())
    }
}
