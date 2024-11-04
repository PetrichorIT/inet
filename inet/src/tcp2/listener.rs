use std::{
    io::{Error, ErrorKind},
    net::SocketAddr,
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc,
    },
};

use tokio::sync::{mpsc, Mutex};

use crate::{
    dns::{lookup_host, ToSocketAddrs},
    socket::Fd,
    IOContext,
};

use super::{Config, TcpStream};

pub struct TcpListener {
    fd: Fd,
    rx: Mutex<mpsc::Receiver<Result<Fd, Error>>>,
    backlog: Arc<AtomicU32>,
}

pub(super) struct Listener {
    pub local_addr: SocketAddr,
    pub tx: mpsc::Sender<Result<Fd, Error>>,
    pub backlog: Arc<AtomicU32>,
    pub config: Config,
}

impl TcpListener {
    pub(super) fn from_raw(
        fd: Fd,
        rx: mpsc::Receiver<Result<Fd, Error>>,
        backlog: Arc<AtomicU32>,
    ) -> Self {
        Self {
            fd,
            rx: Mutex::new(rx),
            backlog,
        }
    }

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
    pub async fn bind<A: ToSocketAddrs>(addr: A) -> Result<TcpListener, Error> {
        let addrs = lookup_host(addr).await?;

        // Get the current context
        IOContext::with_current(|ctx| {
            let mut last_err = None;

            for addr in addrs {
                match ctx.tcp2_bind(addr, None, None) {
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
    pub async fn accept(&self) -> Result<(TcpStream, SocketAddr), Error> {
        loop {
            let mut rx = self.rx.lock().await;
            let Some(fd) = rx.recv().await else {
                return Err(Error::new(ErrorKind::BrokenPipe, "listener closed"));
            };

            self.backlog.fetch_sub(1, Ordering::SeqCst);

            let fd = fd?;
            let stream = TcpStream::from_fd(fd);

            stream.writable().await?;

            let peer = stream.peer_addr()?;
            return Ok((stream, peer));
        }
    }

    /// Returns the local address that this socket is bound to.
    pub fn local_addr(&self) -> Result<SocketAddr, Error> {
        IOContext::with_current(|ctx| ctx.get_socket_addr(self.fd))
    }
    /// Gets the value of the IP_TTL option for this socket.
    ///
    /// For more information about this option, see [set_ttl](TcpListener::set_ttl).
    pub fn ttl(&self) -> Result<u32, Error> {
        IOContext::with_current(|ctx| {
            if let Some(handle) = ctx.tcp2.listeners.get(&self.fd) {
                Ok(handle.config.ttl as u32)
            } else {
                Err(Error::new(ErrorKind::Other, "Lost Tcp"))
            }
        })
    }

    /// Sets the value for the IP_TTL option on this socket.
    ///
    /// This value sets the time-to-live field that is used in every packet sent from this socket.
    pub fn set_ttl(&self, ttl: u32) -> Result<(), Error> {
        IOContext::with_current(|ctx| {
            if let Some(handle) = ctx.tcp2.listeners.get_mut(&self.fd) {
                handle.config.ttl = u8::try_from(ttl).expect("u8");
                Ok(())
            } else {
                Err(Error::new(ErrorKind::Other, "Lost Tcp"))
            }
        })
    }
}

impl Drop for TcpListener {
    fn drop(&mut self) {
        IOContext::try_with_current(|ctx| ctx.tcp2_unbind(self.fd));
    }
}
