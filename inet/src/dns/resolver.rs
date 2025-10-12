use std::future::Future;
use std::io::{Error, ErrorKind, Result};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::pin::Pin;

use crate::IOHandle;

impl IOHandle {
    #[inline]
    pub(crate) async fn lookup_host<T>(self, host: T) -> Result<impl Iterator<Item = SocketAddr>>
    where
        T: ToSocketAddrs,
    {
        <T as sealed::ToSocketAddrsPriv>::to_socket_addrs(&host, self).await
    }
}

pub type DnsResolver =
    fn(&str, u16) -> Pin<Box<dyn Future<Output = Result<Vec<SocketAddr>>> + Send>>;

pub(crate) fn default_dns_resolve(
    _host: &str,
    _port: u16,
) -> Pin<Box<dyn Future<Output = Result<Vec<SocketAddr>>> + Send>> {
    Box::pin(async {
        Err(Error::new(
            ErrorKind::NotFound,
            "name could not be resolved - no dns",
        ))
    })
}

mod sealed {
    use std::net::SocketAddr;

    use crate::IOHandle;

    #[allow(async_fn_in_trait)]
    pub trait ToSocketAddrsPriv {
        type Iter: Iterator<Item = SocketAddr> + Send + 'static;
        async fn to_socket_addrs(&self, handle: IOHandle) -> std::io::Result<Self::Iter>;
    }
}

pub trait ToSocketAddrs: sealed::ToSocketAddrsPriv {}

impl ToSocketAddrs for SocketAddr {}

impl sealed::ToSocketAddrsPriv for SocketAddr {
    type Iter = std::option::IntoIter<SocketAddr>;
    async fn to_socket_addrs(&self, _: IOHandle) -> std::io::Result<Self::Iter> {
        let iter = Some(*self).into_iter();
        Ok(iter)
    }
}

impl ToSocketAddrs for SocketAddrV4 {}

impl sealed::ToSocketAddrsPriv for SocketAddrV4 {
    type Iter = std::option::IntoIter<SocketAddr>;
    async fn to_socket_addrs(&self, handle: IOHandle) -> std::io::Result<Self::Iter> {
        SocketAddr::V4(*self).to_socket_addrs(handle).await
    }
}

impl ToSocketAddrs for SocketAddrV6 {}

impl sealed::ToSocketAddrsPriv for SocketAddrV6 {
    type Iter = std::option::IntoIter<SocketAddr>;
    async fn to_socket_addrs(&self, handle: IOHandle) -> std::io::Result<Self::Iter> {
        SocketAddr::V6(*self).to_socket_addrs(handle).await
    }
}

impl ToSocketAddrs for (IpAddr, u16) {}

impl sealed::ToSocketAddrsPriv for (IpAddr, u16) {
    type Iter = std::option::IntoIter<SocketAddr>;
    async fn to_socket_addrs(&self, _: IOHandle) -> std::io::Result<Self::Iter> {
        let iter = Some(SocketAddr::from(*self)).into_iter();
        Ok(iter)
    }
}

impl ToSocketAddrs for (Ipv4Addr, u16) {}

impl sealed::ToSocketAddrsPriv for (Ipv4Addr, u16) {
    type Iter = std::option::IntoIter<SocketAddr>;
    async fn to_socket_addrs(&self, handle: IOHandle) -> std::io::Result<Self::Iter> {
        let (ip, port) = *self;
        SocketAddrV4::new(ip, port).to_socket_addrs(handle).await
    }
}

impl ToSocketAddrs for (Ipv6Addr, u16) {}

impl sealed::ToSocketAddrsPriv for (Ipv6Addr, u16) {
    type Iter = std::option::IntoIter<SocketAddr>;
    async fn to_socket_addrs(&self, handle: IOHandle) -> std::io::Result<Self::Iter> {
        let (ip, port) = *self;
        SocketAddrV6::new(ip, port, 0, 0)
            .to_socket_addrs(handle)
            .await
    }
}

impl ToSocketAddrs for &[SocketAddr] {}

impl sealed::ToSocketAddrsPriv for &[SocketAddr] {
    type Iter = std::vec::IntoIter<SocketAddr>;
    async fn to_socket_addrs(&self, _: IOHandle) -> std::io::Result<Self::Iter> {
        #[inline]
        fn slice_to_vec(addrs: &[SocketAddr]) -> Vec<SocketAddr> {
            addrs.to_vec()
        }

        // This uses a helper method because clippy doesn't like the `to_vec()`
        // call here (it will allocate, whereas `self.iter().copied()` would
        // not), but it's actually necessary in order to ensure that the
        // returned iterator is valid for the `'static` lifetime, which the
        // borrowed `slice::Iter` iterator would not be.
        //
        // Note that we can't actually add an `allow` attribute for
        // `clippy::unnecessary_to_owned` here, as Tokio's CI runs clippy lints
        // on Rust 1.52 to avoid breaking LTS releases of Tokio. Users of newer
        // Rust versions who see this lint should just ignore it.
        let iter = slice_to_vec(self).into_iter();
        Ok(iter)
    }
}

impl ToSocketAddrs for &str {}

impl sealed::ToSocketAddrsPriv for &str {
    type Iter = std::vec::IntoIter<SocketAddr>;
    async fn to_socket_addrs(&self, handle: IOHandle) -> std::io::Result<Self::Iter> {
        if let Ok(sockaddr) = self.parse() {
            return Ok(vec![sockaddr].into_iter());
        }

        let Some((host, port)) = self.rsplit_once(':') else {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "missing port specification",
            ));
        };

        let port = match port.parse() {
            Ok(port) => port,
            Err(e) => return Err(Error::new(ErrorKind::InvalidInput, e)),
        };

        <(&str, u16) as sealed::ToSocketAddrsPriv>::to_socket_addrs(&(host, port), handle).await
    }
}

impl ToSocketAddrs for (&str, u16) {}

impl sealed::ToSocketAddrsPriv for (&str, u16) {
    type Iter = std::vec::IntoIter<SocketAddr>;
    async fn to_socket_addrs(&self, handle: IOHandle) -> std::io::Result<Self::Iter> {
        if let Ok(ip) = self.0.parse() {
            return Ok(vec![SocketAddr::new(ip, self.1)].into_iter());
        };

        let f = handle.do_io(|ctx| ctx.dns);
        let addrs = f(self.0, self.1).await?;
        Ok(addrs.into_iter())
    }
}

impl ToSocketAddrs for String {}

impl sealed::ToSocketAddrsPriv for String {
    type Iter = std::vec::IntoIter<SocketAddr>;
    async fn to_socket_addrs(&self, handle: IOHandle) -> std::io::Result<Self::Iter> {
        <&str as sealed::ToSocketAddrsPriv>::to_socket_addrs(&self.as_str(), handle).await
    }
}

impl ToSocketAddrs for (String, u16) {}

impl sealed::ToSocketAddrsPriv for (String, u16) {
    type Iter = std::vec::IntoIter<SocketAddr>;
    async fn to_socket_addrs(&self, handle: IOHandle) -> std::io::Result<Self::Iter> {
        <(&str, u16) as sealed::ToSocketAddrsPriv>::to_socket_addrs(&(&self.0, self.1), handle)
            .await
    }
}

#[cfg(test)]
mod tests {
    use std::{net::IpAddr, panic, str::FromStr};

    use des::runtime::RuntimeError;
    use serial_test::serial;

    use crate::{dns::lookup_host, test_util::SimpleSim};

    #[test]
    #[serial]
    fn sample_resolution_without_dns() -> Result<(), RuntimeError> {
        let mut sim = SimpleSim::default();
        sim.node_require_join("192.168.2.101", || async move {
            let _ = lookup_host((IpAddr::from_str("192.168.2.1").unwrap(), 80)).await?;

            let _ = lookup_host("192.168.2.1:80").await?;
            let _ = lookup_host(("192.168.2.1", 80)).await?;

            let _ = lookup_host("192.168.2.1:80".to_string()).await?;
            let _ = lookup_host(("192.168.2.1".to_string(), 80)).await?;
            Ok(())
        });
        sim.run()
    }

    #[test]
    #[serial]
    fn invalid_port() -> Result<(), RuntimeError> {
        let mut sim = SimpleSim::default();
        sim.node_require_join("192.168.2.101", || async move {
            match lookup_host("192.168.2.10".to_string()).await {
                Ok(_) => panic!("should fail"),
                Err(e) => {
                    assert_eq!(e.to_string(), "missing port specification");
                }
            }

            match lookup_host("192.168.2.10:abc".to_string()).await {
                Ok(_) => panic!("should fail"),
                Err(e) => {
                    assert_eq!(e.to_string(), "invalid digit found in string");
                }
            }

            Ok(())
        });
        sim.run()
    }

    #[test]
    #[serial]
    fn no_resolution_without_dns_resolver() -> Result<(), RuntimeError> {
        let mut sim = SimpleSim::default();
        sim.node_require_join("192.168.2.101", || async move {
            match lookup_host("www.test.org:80").await {
                Ok(_) => panic!("should fail"),
                Err(e) => {
                    assert_eq!(e.to_string(), "name could not be resolved - no dns");
                    Ok(())
                }
            }
        });
        sim.run()
    }
}
