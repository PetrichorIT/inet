use des::tokio::sync::{
    mpsc::{channel, Receiver, Sender},
    Mutex,
};
use std::{
    io::{Error, ErrorKind, Result},
    path::Path,
};

use super::SocketAddr;
use crate::{
    socket::{Fd, SocketDomain, SocketType},
    uds::SocketAddrInner,
    IOContext,
};

pub struct UnixDatagram {
    fd: Fd,
    rx: Mutex<Receiver<(Vec<u8>, SocketAddr)>>,
}

#[derive(Debug)]
pub(crate) struct UnixDatagramHandle {
    addr: SocketAddr,
    peer: Option<Fd>,
    tx: Sender<(Vec<u8>, SocketAddr)>,
}

impl PartialEq for UnixDatagramHandle {
    fn eq(&self, other: &Self) -> bool {
        self.addr == other.addr
    }
}
impl Eq for UnixDatagramHandle {}

impl UnixDatagram {
    pub fn local_addr(&self) -> Result<SocketAddr> {
        IOContext::with_current(|ctx| {
            ctx.uds_dgrams
                .get(&self.fd)
                .map(|h| h.addr.clone())
                .ok_or(Error::new(ErrorKind::Other, "socket dropped"))
        })
    }

    pub fn peer_addr(&self) -> Result<SocketAddr> {
        IOContext::with_current(|ctx| {
            ctx.uds_dgrams
                .get(&self.fd)
                .map(|h| {
                    h.peer
                        .map(|fd| ctx.uds_dgrams.get(&fd).map(|f| f.addr.clone()))
                        .flatten()
                        .ok_or(Error::new(ErrorKind::Other, "no peer"))
                })
                .ok_or(Error::new(ErrorKind::Other, "socket dropped"))
        })?
    }

    pub fn bind<P>(path: P) -> Result<UnixDatagram>
    where
        P: AsRef<Path>,
    {
        IOContext::with_current(|ctx| ctx.uds_dgram_bind(path.as_ref()))
    }

    pub fn unbound() -> Result<UnixDatagram> {
        IOContext::with_current(|ctx| ctx.uds_dgram_unbound())
    }

    pub fn pair() -> Result<(UnixDatagram, UnixDatagram)> {
        let a = Self::unbound()?;
        let b = Self::unbound()?;

        IOContext::with_current(|ctx| ctx.uds_dgram_connect_fd(a.fd, b.fd))?;
        IOContext::with_current(|ctx| ctx.uds_dgram_connect_fd(b.fd, a.fd))?;

        Ok((a, b))
    }

    pub fn connect<P>(&self, path: P) -> Result<()>
    where
        P: AsRef<Path>,
    {
        let addr = SocketAddr {
            sockaddr: SocketAddrInner::Path(path.as_ref().to_path_buf()),
        };

        IOContext::with_current(|ctx| ctx.uds_dgram_connect(self.fd, addr))
    }

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

    pub async fn recv(&self, buf: &mut [u8]) -> Result<usize> {
        let peer = self.peer_addr()?;

        let (n, from) = self.recv_from(buf).await?;
        if from == peer {
            Ok(n)
        } else {
            Err(Error::new(ErrorKind::Other, "expected peer packet"))
        }
    }

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

impl IOContext {
    fn uds_dgram_bind(&mut self, path: &Path) -> Result<UnixDatagram> {
        let addr = SocketAddr {
            sockaddr: SocketAddrInner::Path(path.to_path_buf()),
        };

        let entry = self.uds_dgrams.iter().any(|s| s.1.addr == addr);
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

        self.uds_dgrams.insert(fd, handle);
        Ok(socket)
    }

    fn uds_dgram_unbound(&mut self) -> Result<UnixDatagram> {
        let addr = SocketAddr {
            sockaddr: SocketAddrInner::Unnamed,
        };

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

        self.uds_dgrams.insert(fd, handle);
        Ok(socket)
    }

    fn uds_dgram_connect(&mut self, fd: Fd, addr: SocketAddr) -> Result<()> {
        let Some((peer, _)) = self.uds_dgrams.iter().find(|h| h.1.addr == addr) else {
            return Err(Error::new(ErrorKind::ConnectionRefused, "connection refused"))
        };

        self.uds_dgram_connect_fd(fd, *peer)
    }

    fn uds_dgram_connect_fd(&mut self, fd: Fd, peer: Fd) -> Result<()> {
        let Some(handle) = self.uds_dgrams.get_mut(&fd) else {
            return Err(Error::new(ErrorKind::InvalidInput, "no such uds socket exists"))
        };

        handle.peer = Some(peer);
        Ok(())
    }

    fn uds_dgram_get_handle_by_path(
        &mut self,
        dst: &Path,
    ) -> Result<Sender<(Vec<u8>, SocketAddr)>> {
        let dst = SocketAddr {
            sockaddr: SocketAddrInner::Path(dst.to_path_buf()),
        };

        if let Some((_fd, handle)) = self.uds_dgrams.iter().find(|(_, h)| h.addr == dst) {
            Ok(handle.tx.clone())
        } else {
            Err(Error::new(
                ErrorKind::AddrNotAvailable,
                "target addr not found",
            ))
        }
    }

    fn uds_dgram_get_handle_for_peer(&mut self, fd: Fd) -> Result<Sender<(Vec<u8>, SocketAddr)>> {
        let Some(handle) = self.uds_dgrams.get(&fd) else {
            return Err(Error::new(ErrorKind::Other, "socket unbound"))
        };

        let Some(peer_fd) = handle.peer else {
            return Err(Error::new(ErrorKind::Other, "no peer"))
        };

        let Some(peer) = self.uds_dgrams.get(&peer_fd) else {
            return Err(Error::new(ErrorKind::Other, "peer dropped"))
        };

        Ok(peer.tx.clone())
    }
}
