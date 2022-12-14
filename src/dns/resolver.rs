use std::io::Result;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use tokio::net::UdpSocket;

use crate::dns::DNSType;
use crate::{FromBytestream, IntoBytestream};

use super::{DNSMessage, DNSResponseCode};

pub async fn lookup_host<T>(host: T) -> Result<impl Iterator<Item = SocketAddr>>
where
    T: ToSocketAddrs,
{
    <T as sealed::ToSocketAddrsPriv>::to_socket_addrs(&host).await
}

pub trait ToSocketAddrs: sealed::ToSocketAddrsPriv {}

impl ToSocketAddrs for SocketAddr {}
#[async_trait::async_trait]
impl sealed::ToSocketAddrsPriv for SocketAddr {
    type Iter = std::option::IntoIter<SocketAddr>;
    async fn to_socket_addrs(&self) -> std::io::Result<Self::Iter> {
        let iter = Some(*self).into_iter();
        Ok(iter)
    }
}

impl ToSocketAddrs for SocketAddrV4 {}
#[async_trait::async_trait]
impl sealed::ToSocketAddrsPriv for SocketAddrV4 {
    type Iter = std::option::IntoIter<SocketAddr>;
    async fn to_socket_addrs(&self) -> std::io::Result<Self::Iter> {
        SocketAddr::V4(*self).to_socket_addrs().await
    }
}

impl ToSocketAddrs for SocketAddrV6 {}
#[async_trait::async_trait]
impl sealed::ToSocketAddrsPriv for SocketAddrV6 {
    type Iter = std::option::IntoIter<SocketAddr>;
    async fn to_socket_addrs(&self) -> std::io::Result<Self::Iter> {
        SocketAddr::V6(*self).to_socket_addrs().await
    }
}

impl ToSocketAddrs for (IpAddr, u16) {}
#[async_trait::async_trait]
impl sealed::ToSocketAddrsPriv for (IpAddr, u16) {
    type Iter = std::option::IntoIter<SocketAddr>;
    async fn to_socket_addrs(&self) -> std::io::Result<Self::Iter> {
        let iter = Some(SocketAddr::from(*self)).into_iter();
        Ok(iter)
    }
}

impl ToSocketAddrs for (Ipv4Addr, u16) {}
#[async_trait::async_trait]
impl sealed::ToSocketAddrsPriv for (Ipv4Addr, u16) {
    type Iter = std::option::IntoIter<SocketAddr>;
    async fn to_socket_addrs(&self) -> std::io::Result<Self::Iter> {
        let (ip, port) = *self;
        SocketAddrV4::new(ip, port).to_socket_addrs().await
    }
}

impl ToSocketAddrs for (Ipv6Addr, u16) {}
#[async_trait::async_trait]
impl sealed::ToSocketAddrsPriv for (Ipv6Addr, u16) {
    type Iter = std::option::IntoIter<SocketAddr>;
    async fn to_socket_addrs(&self) -> std::io::Result<Self::Iter> {
        let (ip, port) = *self;
        SocketAddrV6::new(ip, port, 0, 0).to_socket_addrs().await
    }
}

impl ToSocketAddrs for &[SocketAddr] {}
#[async_trait::async_trait]
impl sealed::ToSocketAddrsPriv for &[SocketAddr] {
    type Iter = std::vec::IntoIter<SocketAddr>;
    async fn to_socket_addrs(&self) -> std::io::Result<Self::Iter> {
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
#[async_trait::async_trait]
impl sealed::ToSocketAddrsPriv for &str {
    type Iter = std::vec::IntoIter<SocketAddr>;
    async fn to_socket_addrs(&self) -> std::io::Result<Self::Iter> {
        let split = self.split(':').collect::<Vec<_>>();
        if split.len() != 2 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "invalid socket address",
            ));
        }
        let Ok(port) =  split[1].parse::<u16>() else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "invalid socket address",
            ));
        };

        <(&str, u16) as sealed::ToSocketAddrsPriv>::to_socket_addrs(&(&split[0], port)).await
    }
}

impl ToSocketAddrs for (&str, u16) {}
#[async_trait::async_trait]
impl sealed::ToSocketAddrsPriv for (&str, u16) {
    type Iter = std::vec::IntoIter<SocketAddr>;
    async fn to_socket_addrs(&self) -> std::io::Result<Self::Iter> {
        let socket = UdpSocket::bind("127.0.0.1:0").await?;
        let mut question = DNSMessage::question_a(0x01, self.0);
        question.rd = true;
        let buf = question.into_buffer()?;

        let localhost = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 53);
        let n = socket.send_to(&buf, localhost).await?;

        if n != buf.len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "could not send dns query",
            ));
        }

        loop {
            let mut buf = vec![0u8; 512];
            let (n, _) = socket.recv_from(&mut buf).await?;
            buf.truncate(n);

            let mut response = DNSMessage::from_buffer(buf)?;
            assert!(response.qr);

            if response.rcode != DNSResponseCode::NoError {
                match response.rcode {
                    DNSResponseCode::NxDomain => return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "failed to lookup address information: nodename nor servname provided, or not known"
                    )),
                    _ => unimplemented!()
                }
            }

            if !response.anwsers.is_empty() {
                let mut vec = Vec::with_capacity(response.additional.len() + 1);
                let addr = response.anwsers.remove(0).as_addr();
                vec.push(SocketAddr::new(addr, self.1));

                for additional in response.additional {
                    if additional.typ != DNSType::A && additional.typ != DNSType::AAAA {
                        continue;
                    }
                    let addr = additional.as_addr();
                    vec.push(SocketAddr::new(addr, self.1));
                }
                return Ok(vec.into_iter());
            } else {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "Iterative resolve not supported yet",
                ));
            }
        }
    }
}

impl ToSocketAddrs for String {}
#[async_trait::async_trait]
impl sealed::ToSocketAddrsPriv for String {
    type Iter = std::vec::IntoIter<SocketAddr>;
    async fn to_socket_addrs(&self) -> std::io::Result<Self::Iter> {
        <&str as sealed::ToSocketAddrsPriv>::to_socket_addrs(&self.as_str()).await
    }
}

impl ToSocketAddrs for (String, u16) {}
#[async_trait::async_trait]
impl sealed::ToSocketAddrsPriv for (String, u16) {
    type Iter = std::vec::IntoIter<SocketAddr>;
    async fn to_socket_addrs(&self) -> std::io::Result<Self::Iter> {
        <(&str, u16) as sealed::ToSocketAddrsPriv>::to_socket_addrs(&(&self.0, self.1)).await
    }
}

mod sealed {
    use std::net::SocketAddr;

    #[async_trait::async_trait]
    pub trait ToSocketAddrsPriv {
        type Iter: Iterator<Item = SocketAddr> + Send + 'static;
        async fn to_socket_addrs(&self) -> std::io::Result<Self::Iter>;
    }
}
