use std::collections::VecDeque;
use std::io::{Error, ErrorKind, Result};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::task::{Context, Poll};

use crate::inet::tcp::interest::{TcpInterest, TcpInterestGuard};
use crate::inet::tcp::types::{TcpEvent, TcpSyscall};
use crate::inet::{Fd, SocketDomain, SocketType, TcpController, TcpPacket};
use crate::{
    dns::{lookup_host, ToSocketAddrs},
    inet::IOContext,
};

use super::{TcpSocketConfig, TcpStream, TcpStreamInner};

/// A TCP socket server, listening for connections.
///
/// You can accept a new connection by using the [accept](TcpListener::accept) method.
///
/// A TcpListener can be turned into a Stream with TcpListenerStream.
///
/// # Errors
///
/// Note that accepting a connection can lead to various errors and not all of them are necessarily fatal
/// ‒ for example having too many open file descriptors or the other side closing the connection
/// while it waits in an accept queue. These would terminate the stream if not handled in any way.
#[derive(Debug)]
pub struct TcpListener {
    pub(crate) fd: Fd,
}

pub(crate) struct TcpListenerHandle {
    pub(crate) local_addr: SocketAddr,

    pub(crate) incoming: VecDeque<TcpListenerPendingConnection>,
    pub(crate) config: TcpSocketConfig,
    pub(crate) interests: Vec<TcpInterestGuard>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TcpListenerPendingConnection {
    pub(crate) local_addr: SocketAddr,
    pub(crate) peer_addr: SocketAddr,

    pub(crate) packet: (IpAddr, IpAddr, TcpPacket),
}

impl TcpListener {
    /// Creates a new TcpListener, which will be bound to the specified address.
    ///
    /// The returned listener is ready for accepting connections.
    ///
    /// Binding with a port number of 0 will request that the OS assigns a port to this listener.
    /// The port allocated can be queried via the `local_addr` method.
    ///
    /// The address type can be any implementor of the ToSocketAddrs trait.
    /// If addr yields multiple addresses, bind will be attempted with each of the addresses
    /// until one succeeds and returns the listener. If none of the addresses
    /// succeed in creating a listener, the error returned from the
    /// last attempt (the last address) is returned.
    ///
    /// This function sets the SO_REUSEADDR option on the socket.
    pub async fn bind<A: ToSocketAddrs>(addr: A) -> Result<TcpListener> {
        let addrs = lookup_host(addr).await?;

        // Get the current context
        IOContext::with_current(|ctx| {
            let mut last_err = None;

            for addr in addrs {
                match ctx.tcp_bind_listener(addr, None) {
                    Ok(socket) => return Ok(socket),
                    Err(e) => last_err = Some(e),
                }
            }

            Err(last_err.unwrap_or_else(|| {
                Error::new(ErrorKind::InvalidInput, "could not resolve to any address")
            }))
        })
    }

    /// Accepts a new incoming connection from this listener.
    ///
    /// This function will yield once a new TCP connection is established.
    /// When established, the corresponding `TcpStream` and the remote peer’s address will be returned
    pub async fn accept(&self) -> Result<(TcpStream, SocketAddr)> {
        loop {
            let interest = TcpInterest::TcpAccept(self.fd);
            interest.await?;

            let con = IOContext::with_current(|ctx| ctx.tcp_accept(self.fd));

            let (con, peer) = match con {
                Ok(con) => con,
                Err(e) => {
                    if e.kind() == ErrorKind::WouldBlock {
                        continue;
                    }
                    return Err(e);
                }
            };

            let interest = TcpInterest::TcpEstablished(con.inner.fd);
            interest.await?;

            return Ok((con, peer));
        }
    }

    /// DIRTY IMPL
    pub fn poll_accept(&self, _cx: &mut Context<'_>) -> Poll<Result<(TcpStream, SocketAddr)>> {
        IOContext::with_current(|ctx| {
            if let Ok(con) = ctx.tcp_accept(self.fd) {
                Poll::Ready(Ok(con))
            } else {
                Poll::Pending
            }
        })
    }

    /// DEPRECATED
    #[deprecated(note = "Not implemented in simulation context")]
    #[allow(unused)]
    pub fn from_std(_listener: TcpListener) -> Result<TcpListener> {
        unimplemented!()
    }

    /// DEPRECATED
    #[deprecated(note = "Not implemented in simulation context")]
    pub fn into_std(self) -> Result<TcpListener> {
        unimplemented!()
    }

    /// Returns the local address that this socket is bound to.
    pub fn local_addr(&self) -> Result<SocketAddr> {
        IOContext::with_current(|ctx| ctx.bsd_get_socket_addr(self.fd))
    }
    /// Gets the value of the IP_TTL option for this socket.
    ///
    /// For more information about this option, see [set_ttl](TcpListener::set_ttl).
    pub fn ttl(&self) -> Result<u32> {
        IOContext::with_current(|ctx| {
            if let Some(handle) = ctx.tcp_listeners.get(&self.fd) {
                Ok(handle.config.ttl)
            } else {
                Err(Error::new(ErrorKind::Other, "Lost Tcp"))
            }
        })
    }

    /// Sets the value for the IP_TTL option on this socket.
    ///
    /// This value sets the time-to-live field that is used in every packet sent from this socket.
    pub fn set_ttl(&self, ttl: u32) -> Result<()> {
        IOContext::with_current(|ctx| {
            if let Some(handle) = ctx.tcp_listeners.get_mut(&self.fd) {
                handle.config.ttl = ttl;
                Ok(())
            } else {
                Err(Error::new(ErrorKind::Other, "Lost Tcp"))
            }
        })
    }
}

impl Drop for TcpListener {
    fn drop(&mut self) {
        IOContext::try_with_current(|ctx| ctx.tcp_drop_listener(self.fd));
    }
}

impl IOContext {
    fn tcp_bind_listener(
        &mut self,
        addr: SocketAddr,
        config: Option<TcpSocketConfig>,
    ) -> Result<TcpListener> {
        let domain = if addr.is_ipv4() {
            SocketDomain::AF_INET
        } else {
            SocketDomain::AF_INET6
        };
        let fd = self.bsd_create_socket(domain, SocketType::SOCK_STREAM, 0);

        let addr = self.bsd_bind_socket(fd, addr).map_err(|e| {
            self.bsd_close_socket(self.fd);
            e
        })?;

        let buf = TcpListenerHandle {
            local_addr: addr,
            incoming: VecDeque::new(),
            interests: Vec::new(),

            config: config.unwrap_or(TcpSocketConfig::listener(addr)),
        };
        self.tcp_listeners.insert(fd, buf);

        return Ok(TcpListener { fd });
    }

    fn tcp_accept(&mut self, fd: Fd) -> Result<(TcpStream, SocketAddr)> {
        let Some(handle) = self.tcp_listeners.get_mut(&fd) else {
            return Err(Error::new(
                ErrorKind::Other,
                "Simulation context has dropped TcpListener",
            ))
        };

        let con = match handle.incoming.pop_front() {
            Some(con) => con,
            None => return Err(Error::new(ErrorKind::WouldBlock, "WouldBlock")),
        };

        let stream_socket = self.bsd_dup_socket(fd)?;
        let mut ctrl = TcpController::new(stream_socket, self.bsd_get_socket_addr(stream_socket)?);

        self.syscall(stream_socket, TcpSyscall::Listen());

        self.process_state_closed(&mut ctrl, TcpEvent::SysListen());
        self.process_state_listen(&mut ctrl, TcpEvent::Syn(con.packet));

        self.tcp_manager.insert(stream_socket, ctrl);

        inet_trace!(
            "tcp::accept '0x{:x} {} bound to local {}",
            stream_socket,
            con.peer_addr,
            con.local_addr
        );

        Ok((
            TcpStream {
                inner: Arc::new(TcpStreamInner { fd: stream_socket }),
            },
            con.peer_addr,
        ))
    }

    fn tcp_drop_listener(&mut self, fd: Fd) {
        self.tcp_listeners.remove(&fd);
        self.bsd_close_socket(fd);
    }
}
