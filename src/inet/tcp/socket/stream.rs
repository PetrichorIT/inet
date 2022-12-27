use crate::{
    dns::{lookup_host, ToSocketAddrs},
    inet::{
        tcp::{
            interest::TcpInterest,
            types::{TcpEvent, TcpState},
        },
        Fd, IOContext, SocketDomain, SocketType, TcpController,
    },
};
use std::{
    io::{Error, ErrorKind, Result},
    net::{SocketAddr, SocketAddrV6},
};
use std::{
    net::{Ipv4Addr, Ipv6Addr, SocketAddrV4},
    sync::Arc,
};

use super::TcpSocketConfig;

#[derive(Debug)]
pub struct TcpStream {
    pub(crate) inner: Arc<TcpStreamInner>,
}

#[derive(Debug)]
pub(crate) struct TcpStreamInner {
    pub(crate) fd: Fd,
}

impl TcpStream {
    /// Opens a TCP connection to a remote host.
    ///
    /// addr is an address of the remote host.
    /// Anything which implements the ToSocketAddrs trait can be supplied as the address.
    /// If addr yields multiple addresses, connect will be attempted with each of the addresses
    /// until a connection is successful. If none of the addresses result in a successful connection,
    /// the error returned from the last connection attempt (the last address) is returned.
    pub async fn connect<A: ToSocketAddrs>(addr: A) -> Result<TcpStream> {
        let addrs = lookup_host(addr).await?;
        let mut last_err = None;

        for peer in addrs {
            let this = IOContext::with_current(|ctx| ctx.tcp_create_socket(peer, None))?;

            loop {
                // Initiate connect by sending a message (better repeat)
                let interest = TcpInterest::TcpEstablished(this.inner.fd);
                match interest.await {
                    Ok(()) => {}
                    Err(e) => {
                        last_err = Some(e);
                        break;
                    }
                }

                if IOContext::with_current(|ctx| ctx.tcp_connected(this.inner.fd))? {
                    return Ok(this);
                }
            }
        }

        Err(last_err.unwrap_or(Error::new(ErrorKind::Other, "No address worked")))
    }
}

impl IOContext {
    fn tcp_create_socket(
        &mut self,
        peer: SocketAddr,
        config: Option<TcpSocketConfig>,
    ) -> Result<TcpStream> {
        let domain = if peer.is_ipv4() {
            SocketDomain::AF_INET
        } else {
            SocketDomain::AF_INET6
        };
        let unspecified = if peer.is_ipv4() {
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0))
        } else {
            SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0))
        };

        let fd = self.posix_create_socket(domain, SocketType::SOCK_STREAM, 0);
        self.posix_bind_socket(fd, unspecified)?;
        self.posix_bind_peer(fd, peer);

        let mut ctrl = TcpController::new(fd, self.posix_get_socket_addr(fd)?);
        self.process_state_closed(&mut ctrl, TcpEvent::SysOpen(peer));

        self.tcp_manager.insert(fd, ctrl);

        Ok(TcpStream {
            inner: Arc::new(TcpStreamInner { fd }),
        })
    }

    fn tcp_connected(&mut self, fd: Fd) -> Result<bool> {
        let Some(tcp) = self.tcp_manager.get(&fd) else {
            return Err(Error::new(ErrorKind::InvalidInput, "invalid fd - socket dropped"))
        };

        Ok(tcp.state as u8 >= TcpState::Established as u8)
    }
}
