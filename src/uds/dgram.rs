use des::tokio::sync::{
    mpsc::{channel, Receiver, Sender},
    Mutex,
};
use inet_types::uds::SocketAddr;
use std::{
    io::{Error, ErrorKind, Result},
    path::Path,
};

use crate::{
    socket::{Fd, SocketDomain, SocketType},
    IOContext,
};

/// An I/O object representing a Unix datagram socket.
///
/// A socket can be either named (associated with a filesystem path) or unnamed.
///
/// **Note** that in contrast to [tokio::net::UnixDatagram](https://docs.rs/tokio/latest/tokio/net/struct.UnixDatagram.html)
/// named sockets of this implementaion do free the associated file, so are not persistent.
///
/// ## Examples
///
/// Associating a
pub struct UnixDatagram {
    fd: Fd,
    rx: Mutex<Receiver<(Vec<u8>, SocketAddr)>>,
}

#[derive(Debug)]
pub(crate) struct UnixDatagramHandle {
    pub(crate) addr: SocketAddr,
    pub(crate) peer: Option<Fd>,
    tx: Sender<(Vec<u8>, SocketAddr)>,
}

impl PartialEq for UnixDatagramHandle {
    fn eq(&self, other: &Self) -> bool {
        self.addr == other.addr
    }
}
impl Eq for UnixDatagramHandle {}

impl UnixDatagram {
    /// Returns the local bind addr of the socket.
    ///
    /// # Errors
    ///
    /// Returns an error if the socket is invalid.
    pub fn local_addr(&self) -> Result<SocketAddr> {
        IOContext::with_current(|ctx| {
            ctx.uds
                .dgrams
                .get(&self.fd)
                .map(|h| h.addr.clone())
                .ok_or(Error::new(ErrorKind::Other, "socket dropped"))
        })
    }

    /// Returns the peer addr of the socket, set through [`UnixDatagram::connect`].
    ///
    /// # Errors
    ///
    /// Returns an error if the socket is invalid or has no peer addr.
    pub fn peer_addr(&self) -> Result<SocketAddr> {
        IOContext::with_current(|ctx| {
            ctx.uds
                .dgrams
                .get(&self.fd)
                .map(|h| {
                    h.peer
                        .map(|fd| dbg!(ctx.uds.dgrams.get(&fd)).map(|f| f.addr.clone()))
                        .flatten()
                        .ok_or(Error::new(ErrorKind::Other, "no peer"))
                })
                .ok_or(Error::new(ErrorKind::Other, "socket dropped"))
        })?
    }

    /// Creates a new named socket bound to a given filename.
    ///
    /// **Note** that bindings to a filename are exculsive, so no other
    /// socket can bind to the same filename. Additionally the file is
    /// completely locked.
    ///
    /// # Errors
    ///
    /// Returns an error if the file objecct is exclusivly controlled by another socket.
    pub fn bind<P>(path: P) -> Result<UnixDatagram>
    where
        P: AsRef<Path>,
    {
        IOContext::with_current(|ctx| ctx.uds_dgram_bind(path.as_ref()))
    }

    /// Creates a new unnamed socket.
    pub fn unbound() -> Result<UnixDatagram> {
        IOContext::with_current(|ctx| ctx.uds_dgram_unbound())
    }

    /// Creates a pair of unnamed socket, connected to each other
    /// to be used with [`UnixDatagram::send`] / [`UnixDatagram::recv`.]
    ///
    /// # Errors
    ///
    /// May fail because of internal inconsistency.
    pub fn pair() -> Result<(UnixDatagram, UnixDatagram)> {
        let a = Self::unbound()?;
        let b = Self::unbound()?;

        IOContext::with_current(|ctx| ctx.uds_dgram_connect_fd(a.fd, b.fd))?;
        IOContext::with_current(|ctx| ctx.uds_dgram_connect_fd(b.fd, a.fd))?;

        Ok((a, b))
    }

    /// Connects a socket to a peer.
    ///
    /// This allow for the usage of `send` / `recv``.
    /// Note that connecting a socket to a peer socket does not mean the peer
    /// socket connects exclusivly to the inital one.
    ///
    /// # Errors
    ///
    /// May fail if no named socket is found under the given path.
    pub fn connect<P>(&self, path: P) -> Result<()>
    where
        P: AsRef<Path>,
    {
        let addr = SocketAddr::from(path.as_ref().to_path_buf());

        IOContext::with_current(|ctx| ctx.uds_dgram_connect(self.fd, addr))
    }

    /// Sends a datagram to the peer.
    ///
    /// # Errors
    ///
    /// May fail if either the peer is dead, or
    /// no peer was connected.
    pub async fn send(&self, buf: &[u8]) -> Result<usize> {
        let addr = self.local_addr()?;
        let sender = IOContext::with_current(|ctx: &mut IOContext| {
            ctx.uds_dgram_get_handle_for_peer(self.fd)
        })?;
        match sender.send((Vec::from(buf), addr)).await {
            Ok(_) => Ok(buf.len()),
            Err(e) => Err(Error::new(ErrorKind::Other, e)),
        }
    }

    /// Sends a datagram to the another socket.
    ///
    /// # Errors
    ///
    /// May fail if no socket was found under the given address.
    pub async fn send_to<P>(&self, buf: &[u8], target: P) -> Result<usize>
    where
        P: AsRef<Path>,
    {
        let addr = self.local_addr()?;
        let sender = IOContext::with_current(|ctx: &mut IOContext| {
            ctx.uds_dgram_get_handle_by_path(target.as_ref())
        })?;
        match sender.send((Vec::from(buf), addr)).await {
            Ok(_) => Ok(buf.len()),
            Err(e) => Err(Error::new(ErrorKind::Other, e)),
        }
    }

    /// Recevies a datagram from the peer.
    ///
    /// # Errors
    ///
    /// May fail if either the peer is dead, or
    /// no peer was connected.
    pub async fn recv(&self, buf: &mut [u8]) -> Result<usize> {
        let peered =
            IOContext::with_current(|ctx| ctx.uds.dgrams.get(&self.fd).map(|v| v.peer.is_some()))
                .unwrap_or(false);
        if !peered {
            return Err(Error::new(ErrorKind::Other, "no peer"));
        }

        let (n, _from) = self.recv_from(buf).await?;
        // may check _from later
        Ok(n)
    }

    /// Sends a datagram from any other socket.
    pub async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr)> {
        let (bytes, src) = match self.rx.lock().await.recv().await {
            Some(dgram) => dgram,
            None => return Err(Error::new(ErrorKind::Other, "socket closed somehow")),
        };

        let n = buf.len().min(bytes.len());
        buf[..n].copy_from_slice(&bytes[..n]);
        Ok((n, src))
    }
}

impl Drop for UnixDatagram {
    fn drop(&mut self) {
        IOContext::try_with_current(|ctx| ctx.uds_dgram_drop(self.fd));
    }
}

impl IOContext {
    fn uds_dgram_bind(&mut self, path: &Path) -> Result<UnixDatagram> {
        let addr = SocketAddr::from(path.to_path_buf());

        let entry = self.uds.dgrams.iter().any(|s| s.1.addr == addr);
        if entry {
            return Err(Error::new(ErrorKind::AddrInUse, "address already in use"));
        }

        let fd: Fd = self.create_socket(SocketDomain::AF_UNIX, SocketType::SOCK_DGRAM, 0)?;

        let (tx, rx) = channel(64);
        let handle = UnixDatagramHandle {
            addr,
            peer: None,
            tx,
        };
        let socket = UnixDatagram {
            fd,
            rx: Mutex::new(rx),
        };

        self.uds.dgrams.insert(fd, handle);
        Ok(socket)
    }

    fn uds_dgram_unbound(&mut self) -> Result<UnixDatagram> {
        let addr = SocketAddr::unnamed();

        let fd: Fd = self.create_socket(SocketDomain::AF_UNIX, SocketType::SOCK_DGRAM, 0)?;

        let (tx, rx) = channel(64);
        let handle = UnixDatagramHandle {
            addr,
            peer: None,
            tx,
        };
        let socket = UnixDatagram {
            fd,
            rx: Mutex::new(rx),
        };

        self.uds.dgrams.insert(fd, handle);
        Ok(socket)
    }

    fn uds_dgram_connect(&mut self, fd: Fd, addr: SocketAddr) -> Result<()> {
        let Some((peer, _)) = self.uds.dgrams.iter().find(|h| h.1.addr == addr) else {
            return Err(Error::new(ErrorKind::ConnectionRefused, "connection refused"))
        };

        self.uds_dgram_connect_fd(fd, *peer)
    }

    fn uds_dgram_connect_fd(&mut self, fd: Fd, peer: Fd) -> Result<()> {
        let Some(handle) = self.uds.dgrams.get_mut(&fd) else {
            return Err(Error::new(ErrorKind::InvalidInput, "no such uds socket exists"))
        };

        handle.peer = Some(peer);
        Ok(())
    }

    fn uds_dgram_get_handle_by_path(
        &mut self,
        dst: &Path,
    ) -> Result<Sender<(Vec<u8>, SocketAddr)>> {
        let dst = SocketAddr::from(dst.to_path_buf());

        if let Some((_fd, handle)) = self.uds.dgrams.iter().find(|(_, h)| h.addr == dst) {
            Ok(handle.tx.clone())
        } else {
            Err(Error::new(
                ErrorKind::AddrNotAvailable,
                "target addr not found",
            ))
        }
    }

    fn uds_dgram_get_handle_for_peer(&mut self, fd: Fd) -> Result<Sender<(Vec<u8>, SocketAddr)>> {
        let Some(handle) = self.uds.dgrams.get(&fd) else {
            return Err(Error::new(ErrorKind::Other, "socket unbound"))
        };

        let Some(peer_fd) = handle.peer else {
            return Err(Error::new(ErrorKind::Other, "no peer"))
        };

        let Some(peer) = self.uds.dgrams.get(&peer_fd) else {
            return Err(Error::new(ErrorKind::Other, "peer dropped"))
        };

        Ok(peer.tx.clone())
    }

    fn uds_dgram_drop(&mut self, fd: Fd) {
        self.uds.dgrams.remove(&fd);
        let _ = self.close_socket(fd);
    }
}
