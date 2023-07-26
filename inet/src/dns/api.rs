use crate::ctx::IOContext;

use super::{resolver, DnsResolver};
use std::io::Result;
use std::net::SocketAddr;

pub async fn lookup_host<T>(host: T) -> Result<impl Iterator<Item = SocketAddr>>
where
    T: resolver::ToSocketAddrs,
{
    resolver::lookup_host(host).await
}

pub fn set_dns_resolver(resolver: DnsResolver) -> Result<()> {
    IOContext::failable_api(|ctx| ctx.set_dns_resolver(resolver))
}

impl IOContext {
    fn set_dns_resolver(&mut self, resolver: DnsResolver) -> Result<()> {
        self.dns = resolver;
        Ok(())
    }
}
