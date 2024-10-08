use std::collections::VecDeque;
use std::io::{Error, ErrorKind, Result};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

use crate::socket::*;
use crate::tcp::interest::{TcpInterest, TcpInterestGuard};
use crate::tcp::util::{TcpEvent, TcpSyscall};
use crate::tcp::{TcpPacket, TcpSocketConfig, TransmissionControlBlock};
use crate::{
    dns::{lookup_host, ToSocketAddrs},
    IOContext,
};

use tokio::sync::{
    mpsc::{self, Receiver, Sender},
    oneshot, Mutex,
};
use types::ip::IpPacketRef;

use super::{TcpStream, TcpStreamInner};

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
    pub(crate) rx: Mutex<Receiver<IncomingConnection>>,
    pub(crate) backlog: Arc<AtomicU32>,
}

#[derive(Debug)]
pub(crate) struct ListenerHandle {
    pub(crate) local_addr: SocketAddr,
    pub(crate) tx: Sender<IncomingConnection>,
    pub(crate) backlog: Arc<AtomicU32>,
    pub(crate) config: TcpSocketConfig,
    pub(crate) interests: Vec<TcpInterestGuard>,
}

type IncomingConnection = Result<(TcpStream, oneshot::Receiver<Result<()>>)>;

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
                match ctx.tcp_bind_listener(addr, None, None) {
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
            let mut rx = self.rx.lock().await;
            let Some(con) = rx.recv().await else {
                return Err(Error::new(ErrorKind::BrokenPipe, "listener closed"));
            };

            self.backlog.fetch_sub(1, Ordering::SeqCst);

            let (stream, ready) = con?;
            ready.await.expect("Did not expect recv error")?;

            let peer = stream.peer_addr()?;
            return Ok((stream, peer));
        }
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
        IOContext::with_current(|ctx| ctx.get_socket_addr(self.fd))
    }
    /// Gets the value of the IP_TTL option for this socket.
    ///
    /// For more information about this option, see [set_ttl](TcpListener::set_ttl).
    pub fn ttl(&self) -> Result<u32> {
        IOContext::with_current(|ctx| {
            if let Some(handle) = ctx.tcp.listeners.get(&self.fd) {
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
            if let Some(handle) = ctx.tcp.listeners.get_mut(&self.fd) {
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
    pub(super) fn tcp_bind_listener(
        &mut self,
        mut addr: SocketAddr,
        config: Option<TcpSocketConfig>,
        fd: Option<Fd>,
    ) -> Result<TcpListener> {
        let (fd) = if let Some(fd) = fd {
            fd
        } else {
            let domain = if addr.is_ipv4() {
                SocketDomain::AF_INET
            } else {
                SocketDomain::AF_INET6
            };
            let fd = self.create_socket(domain, SocketType::SOCK_STREAM, 0)?;

            addr = self.bind_socket(fd, addr).map_err(|e| {
                self.close_socket(self.fd);
                e
            })?;
            fd
        };

        let (tx, rx) =
            mpsc::channel(config.as_ref().map(|c| c.listen_backlog).unwrap_or(32) as usize);

        let backlog = Arc::new(AtomicU32::new(0));
        let buf = ListenerHandle {
            local_addr: addr,
            backlog: backlog.clone(),
            tx,
            interests: Vec::new(),

            config: config.unwrap_or(self.tcp.config.listener(addr)),
        };
        self.tcp.listeners.insert(fd, buf);

        return Ok(TcpListener {
            fd,
            rx: Mutex::new(rx),
            backlog,
        });
    }

    pub(super) fn tcp_drop_listener(&mut self, fd: Fd) {
        self.tcp.listeners.remove(&fd);
        self.close_socket(fd);
    }
}
