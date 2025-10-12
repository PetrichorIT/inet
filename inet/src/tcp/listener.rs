use std::{
    fmt::Debug,
    io::{Error, ErrorKind},
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    },
};

use des::net::module::try_current;
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, mpsc};
use valuable::Valuable;

use crate::{
    IOHandle,
    dns::{ToSocketAddrs, lookup_host},
    ioctx,
    socket::Fd,
};

use super::{Config, TcpStream};

pub struct TcpListener {
    fd: Fd,
    rx: Mutex<mpsc::Receiver<Result<Fd, Error>>>,
    handle: IOHandle,
    backlog: Arc<AtomicU32>,
}

pub(super) struct Listener {
    pub local_addr: SocketAddr,
    pub tx: mpsc::Sender<Result<Fd, Error>>,
    pub backlog: Arc<AtomicU32>,
    pub backlog_limit: u32,
    pub config: Config,
}

#[derive(Debug, Valuable, Serialize, Deserialize)]
pub struct ListenerInfo {}

impl Listener {
    pub fn create(
        local_addr: SocketAddr,
        config: Config,
        backlog_limit: usize,
    ) -> (Self, mpsc::Receiver<Result<Fd, Error>>, Arc<AtomicU32>) {
        let (tx, rx) = mpsc::channel(backlog_limit);
        let backlog = Arc::new(AtomicU32::new(0));
        let handle = Self {
            local_addr,
            tx,
            backlog: backlog.clone(),
            backlog_limit: backlog_limit as u32,
            config,
        };

        handle.publish();
        (handle, rx, backlog)
    }

    pub fn info(&self) -> ListenerInfo {
        ListenerInfo {}
    }

    pub fn publish(&self) {
        if cfg!(feature = "props") {
            let Some(module) = try_current() else { return };
            module
                .prop::<ListenerInfo>(&format!("inet.tcp2.listener.{}", self.local_addr))
                .expect("typing failed")
                .set(self.info());
        }
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        if cfg!(feature = "props") {
            let Some(module) = try_current() else { return };
            module
                .prop_raw(&format!("inet.tcp2.listener.{}", self.local_addr))
                .clear()
        }
    }
}

impl TcpListener {
    pub(super) fn from_raw(
        fd: Fd,
        rx: mpsc::Receiver<Result<Fd, Error>>,
        handle: IOHandle,
        backlog: Arc<AtomicU32>,
    ) -> Self {
        Self {
            fd,
            handle,
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
        ioctx().do_io(|ctx| {
            let mut last_err = None;

            for addr in addrs {
                match ctx.tcp_bind(addr, None, None, None) {
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
        let mut rx = self.rx.lock().await;
        let Some(fd) = rx.recv().await else {
            return Err(Error::new(ErrorKind::BrokenPipe, "listener closed"));
        };

        self.backlog.fetch_sub(1, Ordering::SeqCst);

        let stream = TcpStream::from_fd(fd?, self.handle.clone());
        stream.writable().await?;

        let peer = stream.peer_addr()?;
        Ok((stream, peer))
    }

    /// Returns the local address that this socket is bound to.
    pub fn local_addr(&self) -> Result<SocketAddr, Error> {
        self.handle.do_io(|ctx| ctx.socket_get_addr(self.fd))
    }
    /// Gets the value of the IP_TTL option for this socket.
    ///
    /// For more information about this option, see [set_ttl](TcpListener::set_ttl).
    pub fn ttl(&self) -> Result<u32, Error> {
        self.handle.do_io(|ctx| {
            if let Some(handle) = ctx.tcp.listeners.get(&self.fd) {
                Ok(handle.config.ttl as u32)
            } else {
                Err(Error::other("Lost Tcp"))
            }
        })
    }

    /// Sets the value for the IP_TTL option on this socket.
    ///
    /// This value sets the time-to-live field that is used in every packet sent from this socket.
    pub fn set_ttl(&self, ttl: u32) -> Result<(), Error> {
        self.handle.do_io(|ctx| {
            if let Some(handle) = ctx.tcp.listeners.get_mut(&self.fd) {
                handle.config.ttl = u8::try_from(ttl).expect("u8");
                Ok(())
            } else {
                Err(Error::other("Lost Tcp"))
            }
        })
    }
}

impl Debug for TcpListener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TcpListener").field("fd", &self.fd).finish()
    }
}

impl Drop for TcpListener {
    fn drop(&mut self) {
        self.handle.try_do_io(|ctx| ctx.tcp_unbind(self.fd));
    }
}
