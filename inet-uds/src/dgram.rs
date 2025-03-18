use bytes_io::Bytes;
use inet::{
    extensions::{try_with_ext, with_ext},
    socket::{close, socket},
};
use std::{
    io::{Error, ErrorKind},
    path::Path,
};
use tokio::sync::{
    mpsc::{channel, Receiver, Sender},
    Mutex,
};

use inet::socket::{Fd, SocketDomain, SocketType};

use crate::{addr::SocketAddr, UdsExtension};

/// An I/O object representing a Unix datagram socket.
///
/// A socket can be either named (associated with a filesystem path) or unnamed.
///
/// **Note** that in contrast to [tokio::net::UnixDatagram](https://docs.rs/tokio/latest/tokio/net/struct.UnixDatagram.html)
/// named sockets of this implementaion do free the associated file, so are not persistent.
///
/// ## Examples
///
#[derive(Debug)]
pub struct UnixDatagram {
    fd: Fd,
    rx: Mutex<Receiver<(Bytes, SocketAddr)>>,
}

#[derive(Debug)]
pub(crate) struct UnixDatagramHandle {
    pub(crate) addr: SocketAddr,
    pub(crate) peer: Option<Fd>,
    tx: Sender<(Bytes, SocketAddr)>,
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
    pub fn local_addr(&self) -> Result<SocketAddr, Error> {
        with_ext::<UdsExtension, _>(|uds| {
            uds.dgrams
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
    pub fn peer_addr(&self) -> Result<SocketAddr, Error> {
        with_ext::<UdsExtension, _>(|uds| {
            uds.dgrams
                .get(&self.fd)
                .map(|h| {
                    h.peer
                        .map(|fd| dbg!(uds.dgrams.get(&fd)).map(|f| f.addr.clone()))
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
    pub fn bind<P>(path: P) -> Result<UnixDatagram, Error>
    where
        P: AsRef<Path>,
    {
        let fd: Fd = socket(SocketDomain::AF_UNIX, SocketType::SOCK_DGRAM, 0)?;
        with_ext::<UdsExtension, _>(|uds| {
            let path: &Path = path.as_ref();
            let addr = SocketAddr::from(path.to_path_buf());

            if uds.dgrams.values().any(|s| s.addr == addr) {
                return Err(Error::new(ErrorKind::AddrInUse, "address already in use"));
            }

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

            uds.dgrams.insert(fd, handle);
            Ok(socket)
        })
    }

    /// Creates a new unnamed socket.
    pub fn unbound() -> Result<UnixDatagram, Error> {
        let fd: Fd = socket(SocketDomain::AF_UNIX, SocketType::SOCK_DGRAM, 0)?;
        with_ext::<UdsExtension, _>(|uds| {
            let addr = SocketAddr::unnamed();

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

            uds.dgrams.insert(fd, handle);
            Ok(socket)
        })
    }

    /// Creates a pair of unnamed socket, connected to each other
    /// to be used with [`UnixDatagram::send`] / [`UnixDatagram::recv`.]
    ///
    /// # Errors
    ///
    /// May fail because of internal inconsistency.
    pub fn pair() -> Result<(UnixDatagram, UnixDatagram), Error> {
        let a = Self::unbound()?;
        let b = Self::unbound()?;

        with_ext::<UdsExtension, _>(|uds| uds.connect_dgram(a.fd, b.fd))?;
        with_ext::<UdsExtension, _>(|uds| uds.connect_dgram(b.fd, a.fd))?;

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
    pub fn connect<P>(&self, path: P) -> Result<(), Error>
    where
        P: AsRef<Path>,
    {
        let addr = SocketAddr::from(path.as_ref().to_path_buf());

        with_ext::<UdsExtension, _>(|uds| {
            let Some((peer, _)) = uds.dgrams.iter().find(|h| h.1.addr == addr) else {
                return Err(Error::new(
                    ErrorKind::ConnectionRefused,
                    "connection refused",
                ));
            };

            uds.connect_dgram(self.fd, *peer)
        })
    }

    /// Sends a datagram to the peer.
    ///
    /// # Errors
    ///
    /// May fail if either the peer is dead, or
    /// no peer was connected.
    pub async fn send(&self, buf: &[u8]) -> Result<usize, Error> {
        let addr = self.local_addr()?;
        let sender = with_ext::<UdsExtension, _>(|uds| {
            let fd = self.fd;
            let Some(handle) = uds.dgrams.get(&fd) else {
                return Err(Error::new(ErrorKind::Other, "socket unbound"));
            };

            let Some(peer_fd) = handle.peer else {
                return Err(Error::new(ErrorKind::Other, "no peer"));
            };

            let Some(peer) = uds.dgrams.get(&peer_fd) else {
                return Err(Error::new(ErrorKind::Other, "peer dropped"));
            };

            Ok(peer.tx.clone())
        })?;
        match sender.send((Bytes::from(buf.to_vec()), addr)).await {
            Ok(_) => Ok(buf.len()),
            Err(e) => Err(Error::new(ErrorKind::Other, e)),
        }
    }

    /// Sends a datagram to the another socket.
    ///
    /// # Errors
    ///
    /// May fail if no socket was found under the given address.
    pub async fn send_to<P>(&self, buf: &[u8], target: P) -> Result<usize, Error>
    where
        P: AsRef<Path>,
    {
        let addr = self.local_addr()?;
        let sender = with_ext::<UdsExtension, _>(|uds| {
            let target = SocketAddr::from(target.as_ref().to_path_buf());
            if let Some((_, handle)) = uds.dgrams.iter().find(|(_, h)| h.addr == target) {
                Ok(handle.tx.clone())
            } else {
                Err(Error::new(
                    ErrorKind::AddrNotAvailable,
                    "target addr not found",
                ))
            }
        })?;
        match sender.send((Bytes::from(buf.to_vec()), addr)).await {
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
    pub async fn recv(&self, buf: &mut [u8]) -> Result<usize, Error> {
        let peered =
            with_ext::<UdsExtension, _>(|uds| uds.dgrams.get(&self.fd).map(|v| v.peer.is_some()))
                .unwrap_or(false);
        if !peered {
            return Err(Error::new(ErrorKind::Other, "no peer"));
        }

        let (n, _from) = self.recv_from(buf).await?;
        // may check _from later
        Ok(n)
    }

    /// Sends a datagram from any other socket.
    pub async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr), Error> {
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
        try_with_ext::<UdsExtension, _>(|uds| uds.dgrams.remove(&self.fd));
        let _ = close(self.fd);
    }
}

impl UdsExtension {
    fn connect_dgram(&mut self, fd: Fd, peer: Fd) -> Result<(), Error> {
        let Some(handle) = self.dgrams.get_mut(&fd) else {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "no such uds socket exists",
            ));
        };

        handle.peer = Some(peer);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::{iter::repeat_with, time::Duration};

    use super::*;

    use des::{
        net::{AsyncFn, Sim},
        runtime::{random, Builder, RuntimeError},
        time::sleep,
    };
    use serial_test::serial;

    #[serial]
    #[test]
    fn cannot_bind_to_same_addr() {
        let mut sim = Sim::new(()).with_stack(inet::init);

        sim.node(
            "alice",
            AsyncFn::io(|_| async move {
                let _uds = UnixDatagram::bind("/usr/link")?;
                let error = UnixDatagram::bind("/usr/link").unwrap_err();
                assert_eq!(error.kind(), ErrorKind::AddrInUse);
                assert_eq!(error.to_string(), "address already in use");

                Ok(())
            }),
        );

        let _ = Builder::seeded(123).max_time(100.0.into()).build(sim).run();
    }

    #[serial]
    #[test]
    fn unnamed_pair_has_peer_addr() {
        let mut sim = Sim::new(()).with_stack(inet::init);

        sim.node(
            "alice",
            AsyncFn::io(|_| async move {
                let (lhs, rhs) = UnixDatagram::pair()?;
                assert_eq!(lhs.peer_addr()?, SocketAddr::unnamed());
                assert_eq!(rhs.peer_addr()?, SocketAddr::unnamed());

                Ok(())
            }),
        );

        let _ = Builder::seeded(123).max_time(100.0.into()).build(sim).run();
    }

    #[serial]
    #[test]
    fn unamed_pair_connectivity() -> Result<(), RuntimeError> {
        let mut app = Sim::new(()).with_stack(inet::init);
        app.node(
            "main",
            AsyncFn::io(|_| async move {
                let (a, b) = UnixDatagram::pair().unwrap();

                let h1 = tokio::spawn(async move {
                    for _i in 0..10 {
                        a.send(&[1, 2, 3]).await.unwrap();
                        sleep(Duration::from_secs_f64(random())).await;
                    }

                    for _i in 0..10 {
                        a.recv(&mut [0; 500]).await.unwrap();
                    }
                });

                let h2 = tokio::spawn(async move {
                    for _i in 0..10 {
                        b.send(&[1, 2, 3]).await.unwrap();
                        sleep(Duration::from_secs_f64(random())).await;
                    }

                    for _i in 0..10 {
                        b.recv(&mut [0; 500]).await.unwrap();
                    }
                });

                h1.await?;
                h2.await?;

                Ok(())
            })
            .require_join(),
        );
        Builder::seeded(123)
            .max_time(100.0.into())
            .build(app)
            .run()
            .map(|_| ())
    }

    #[serial]
    #[test]
    fn connected_can_transmit_datagrams() -> Result<(), RuntimeError> {
        let mut sim = Sim::new(()).with_stack(inet::init);

        sim.node(
            "alice",
            AsyncFn::io(|_| async move {
                let (lhs, rhs) = UnixDatagram::pair()?;

                let h1 = tokio::spawn(async move {
                    let mut buf = [0; 1024];
                    let n = lhs.recv(&mut buf).await.unwrap();
                    assert_eq!(buf[..n], [1, 2, 3, 4, 5, 6]);
                });
                let h2 = tokio::spawn(async move {
                    rhs.send(&[1, 2, 3, 4, 5, 6]).await.unwrap();
                });

                h1.await.unwrap();
                h2.await.unwrap();
                Ok(())
            }),
        );

        Builder::seeded(123)
            .max_time(100.0.into())
            .build(sim)
            .run()
            .map(|_| ())
    }

    #[serial]
    #[test]
    fn named_connectivity() -> Result<(), RuntimeError> {
        let mut app = Sim::new(()).with_stack(inet::init);
        app.node(
            "main",
            AsyncFn::io(|_| async move {
                let h1 = tokio::spawn(async move {
                    let sock = UnixDatagram::bind("/tmp/task1").unwrap();
                    sleep(Duration::from_secs(1)).await;

                    // Echo
                    for _ in 0..10 {
                        let mut buf = [0; 512];
                        let (n, from) = sock.recv_from(&mut buf).await.unwrap();

                        sock.send_to(&buf[..n], from.as_pathname().unwrap())
                            .await
                            .unwrap();
                    }
                });

                let h2 = tokio::spawn(async move {
                    let sock = UnixDatagram::bind("/tmp/task2").unwrap();
                    for _i in 0..3 {
                        let n = 200 + random::<u64>() as usize % 200;
                        let buf = repeat_with(|| random::<u8>()).take(n).collect::<Vec<_>>();

                        sock.send_to(&buf, "/tmp/task1").await.unwrap();
                        let mut rbuf = [0; 512];
                        let (nn, _from) = sock.recv_from(&mut rbuf).await.unwrap();

                        assert_eq!(n, nn);
                        assert_eq!(buf[..n], rbuf[..n]);

                        sleep(Duration::from_secs_f64(random())).await;
                    }
                });

                let h3 = tokio::spawn(async move {
                    let sock = UnixDatagram::bind("/tmp/task3").unwrap();
                    for _i in 0..7 {
                        let n = 200 + random::<u64>() as usize % 200;
                        let buf = repeat_with(|| random::<u8>()).take(n).collect::<Vec<_>>();

                        sock.send_to(&buf, "/tmp/task1").await.unwrap();
                        let mut rbuf = [0; 512];
                        let (nn, _from) = sock.recv_from(&mut rbuf).await.unwrap();

                        assert_eq!(n, nn);
                        assert_eq!(buf[..n], rbuf[..n]);

                        sleep(Duration::from_secs_f64(random())).await;
                    }
                });

                h1.await?;
                h2.await?;
                h3.await?;
                Ok(())
            })
            .require_join(),
        );
        let rt = Builder::seeded(123).max_time(100.0.into()).build(app);
        rt.run().map(|_| ())
    }

    #[serial]
    #[test]
    fn named_tempdir() {
        let mut app = Sim::new(()).with_stack(inet::init);
        app.node(
            "main",
            AsyncFn::io(|_| async move {
                let tmp = inet::env::fs::tempdir().unwrap();

                // Bind each socket to a filesystem path
                let tx_path = tmp.path().join("tx");
                let tx = UnixDatagram::bind(&tx_path)?;
                let rx_path = tmp.path().join("rx");
                let rx = UnixDatagram::bind(&rx_path)?;

                tracing::info!("tx: {tx_path:?} rx: {rx_path:?}");

                let bytes = b"hello world";
                tx.send_to(bytes, &rx_path).await?;

                let mut buf = vec![0u8; 24];
                let (size, addr) = rx.recv_from(&mut buf).await?;

                let dgram = &buf[..size];
                assert_eq!(dgram, bytes);
                assert_eq!(addr.as_pathname().unwrap(), &tx_path);
                Ok(())
            })
            .require_join(),
        );
        let _ = Builder::seeded(123).max_time(100.0.into()).build(app).run();
    }
}
