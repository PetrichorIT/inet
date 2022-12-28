use tokio::io::{Interest, Ready};

use crate::{
    dns::{lookup_host, ToSocketAddrs},
    inet::{udp::UDPPacket, Fd, IOContext, InterfaceName},
};
use std::{
    io::{Error, ErrorKind, Result},
    net::SocketAddr,
};

use super::interest::UdpInterest;

#[derive(Debug)]
pub struct UdpSocket {
    pub(super) fd: Fd,
}

impl UdpSocket {
    /// This function will create a new UDP socket and attempt to bind it to the `addr` provided.
    ///
    /// Binding with a port number of 0 will request that the OS assigns a port to this listener.
    /// The port allocated can be queried via the `local_addr` method.
    pub async fn bind(addr: impl ToSocketAddrs) -> Result<UdpSocket> {
        let addrs = lookup_host(addr).await?;

        // Get the current context
        IOContext::with_current(|ctx| {
            let mut last_err = None;

            for addr in addrs {
                match ctx.udp_bind(addr) {
                    Ok(socket) => return Ok(socket),
                    Err(e) => last_err = Some(e),
                }
            }

            Err(last_err.unwrap_or_else(|| {
                Error::new(ErrorKind::InvalidInput, "could not resolve to any address")
            }))
        })
    }

    /// This call is deprecated, since simulated sockets should not be
    /// base on real sockets managed by the OS.
    #[deprecated(note = "Cannot create simulated socket from std::net::UdpSocket")]
    #[allow(unused)]
    pub fn from_std(socket: std::net::UdpSocket) -> Result<UdpSocket> {
        panic!("No implemented for feature 'sim'")
    }

    /// This call is deprecated, since simulated sockets should not be
    /// base on real sockets managed by the OS.
    #[deprecated(note = "Cannot extract std::net::UdpSocket from simulated socket")]
    pub fn into_std(self) -> Result<std::net::UdpSocket> {
        panic!("No implemented for feature 'sim'")
    }

    /// Returns the local address that this socket is bound to.
    pub fn local_addr(&self) -> Result<SocketAddr> {
        IOContext::with_current(|ctx| ctx.bsd_get_socket_addr(self.fd))
    }

    /// Returns the peer address that this socket is bound to.
    pub fn peer_addr(&self) -> Result<SocketAddr> {
        IOContext::with_current(|ctx| ctx.bsd_get_socket_peer(self.fd))
    }

    /// Connects the UDP socket setting the default destination for send() and
    /// limiting packets that are read via recv from the address specified in `addr`.
    pub async fn connect<A: ToSocketAddrs>(&self, addr: A) -> Result<()> {
        let addrs = lookup_host(addr).await?;

        IOContext::with_current(|ctx| {
            let mut last_err = None;
            for peer in addrs {
                match ctx.udp_connect(self.fd, peer) {
                    Ok(()) => return Ok(()),
                    Err(e) => last_err = Some(e),
                }
            }

            Err(last_err.unwrap())
        })
    }

    /// Waits for any of the requested ready states.
    ///
    /// This function is usually paired with `try_recv()` or `try_send()`.
    /// It can be used to concurrently recv / send to the same socket on a single task without
    /// splitting the socket.
    ///
    /// The function may complete without the socket being ready.
    /// This is a false-positive and attempting an operation will return with `io::ErrorKind::WouldBlock`.
    pub async fn ready(&self, interest: Interest) -> Result<Ready> {
        let io = UdpInterest {
            fd: self.fd,
            io_interest: interest,
            resolved: false,
        };

        io.await
    }

    /// Waits for the socket to become writable.
    ///
    /// This function is equivalent to `ready(Interest::WRITABLE)` and is usually
    /// paired with `try_send()` or `try_send_to()`.
    ///
    /// The function may complete without the socket being writable.
    /// This is a false-positive and attempting a `try_send()` will return with `io::ErrorKind::WouldBlock`.
    pub async fn writable(&self) -> Result<()> {
        self.ready(Interest::WRITABLE).await?;
        Ok(())
    }

    /// Sends data on the socket to the remote address that the socket is connected to.
    ///
    /// The [connect](UdpSocket::connect) method will connect this socket to a remote address.
    /// This method will fail if the socket is not connected.
    pub async fn send(&self, buf: &[u8]) -> Result<usize> {
        loop {
            self.writable().await?;
            let peer = self.peer_addr()?;
            let result = IOContext::with_current(|ctx| ctx.udp_send_to(self.fd, peer, buf));

            match result {
                Ok(v) => return Ok(v),
                Err(e) if e.kind() == ErrorKind::WouldBlock => continue,
                Err(e) => return Err(e),
            }
        }
    }

    /// Tries to send data on the socket to the remote address to which it is connected.
    ///
    /// When the socket buffer is full, Err(io::ErrorKind::WouldBlock) is returned.
    /// This function is usually paired with writable().
    pub fn try_send(&self, buf: &[u8]) -> Result<usize> {
        let peer = self.peer_addr()?;
        IOContext::with_current(|ctx| ctx.udp_send_to(self.fd, peer, buf))
    }

    /// Sends data on the socket to the given address. On success, returns the number of bytes written.
    ///
    /// Address type can be any implementor of [ToSocketAddrs] trait. See its documentation for concrete examples.
    ///
    /// It is possible for `addr` to yield multiple addresses,
    /// but `send_to` will only send data to the first address yielded by `addr`.
    pub async fn send_to(&self, buf: &[u8], target: impl ToSocketAddrs) -> Result<usize> {
        let addr = lookup_host(target).await;
        let first = addr.unwrap().next().unwrap();

        loop {
            self.writable().await?;
            let result = IOContext::with_current(|ctx| ctx.udp_send_to(self.fd, first, buf));

            match result {
                Ok(v) => return Ok(v),
                Err(e) if e.kind() == ErrorKind::WouldBlock => continue,
                Err(e) => return Err(e),
            }
        }
    }

    /// Tries to send data on the socket to the given address,
    /// but if the send is blocked this will return right away.
    ///
    /// This function is usually paired with writable().
    pub fn try_send_to(&self, buf: &[u8], target: SocketAddr) -> Result<usize> {
        IOContext::with_current(|ctx| ctx.udp_send_to(self.fd, target, buf))?;
        Ok(buf.len())
    }

    /// Waits for the socket to become readable.
    ///
    /// This function is equivalent to `ready(Interest::READABLE)` and is usually paired with `try_recv()`.
    ///
    /// The function may complete without the socket being readable.
    /// This is a false-positive and attempting a `try_recv()` will return with `io::ErrorKind::WouldBlock`.
    pub async fn readable(&self) -> Result<()> {
        self.ready(Interest::READABLE).await?;
        Ok(())
    }

    /// Receives a single datagram message on the socket from the remote address to
    /// which it is connected. On success, returns the number of bytes read.
    pub async fn recv(&self, buf: &mut [u8]) -> Result<usize> {
        let peer = self.peer_addr()?;
        loop {
            self.readable().await?;

            let r = IOContext::with_current(|ctx| {
                if let Some(handle) = ctx.udp_manager.get_mut(&self.fd) {
                    handle.incoming.pop_front()
                } else {
                    panic!("SimContext lost socket")
                }
            });

            match r {
                Some((src, _, msg)) => {
                    if src != peer {
                        continue;
                    }

                    let wrt = msg.content.len().min(buf.len());
                    for i in 0..wrt {
                        buf[i] = msg.content[i];
                    }

                    return Ok(wrt);
                }
                None => {}
            }
        }
    }

    /// Tries to receive a single datagram message on the socket from the remote address to which it is connected.
    /// On success, returns the number of bytes read.
    ///
    /// The function must be called with valid byte array buf of sufficient size to hold the message bytes.
    /// If a message is too long to fit in the supplied buffer, excess bytes may be discarded.
    pub fn try_recv(&self, buf: &mut [u8]) -> Result<usize> {
        loop {
            let peer = self.peer_addr()?;
            let (peer, r) = IOContext::with_current(|ctx| {
                if let Some(handle) = ctx.udp_manager.get_mut(&self.fd) {
                    Ok::<(SocketAddr, Option<(SocketAddr, SocketAddr, UDPPacket)>), std::io::Error>(
                        (peer, handle.incoming.pop_front()),
                    )
                } else {
                    panic!("SimContext lost socket")
                }
            })?;

            match r {
                Some((src, _, msg)) => {
                    if src != peer {
                        continue;
                    }

                    let wrt = msg.content.len().min(buf.len());
                    for i in 0..wrt {
                        buf[i] = msg.content[i];
                    }

                    return Ok(wrt);
                }
                None => return Err(Error::new(ErrorKind::WouldBlock, "Would block")),
            }
        }
    }

    /// Receives a single datagram message on the socket. On success,
    /// returns the number of bytes read and the origin.
    ///
    /// The function must be called with valid byte array buf of sufficient size to hold the message bytes.
    /// If a message is too long to fit in the supplied buffer, excess bytes may be discarded.
    pub async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr)> {
        loop {
            self.readable().await?;

            let r = IOContext::with_current(|ctx| {
                if let Some(handle) = ctx.udp_manager.get_mut(&self.fd) {
                    handle.incoming.pop_front()
                } else {
                    panic!("SimContext lost socket")
                }
            });

            match r {
                Some((src, _, msg)) => {
                    let wrt = msg.content.len().min(buf.len());
                    for i in 0..wrt {
                        buf[i] = msg.content[i];
                    }

                    return Ok((wrt, src));
                }
                None => return Err(Error::new(ErrorKind::WouldBlock, "Would block")),
            }
        }
    }

    /// Tries to receive a single datagram message on the socket.
    /// On success, returns the number of bytes read and the origin.
    ///
    /// The function must be called with valid byte array buf of sufficient size
    /// to hold the message bytes. If a message is too long to fit in the supplied buffer,
    /// excess bytes may be discarded.
    pub fn try_recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr)> {
        loop {
            let r = IOContext::with_current(|ctx| {
                if let Some(handle) = ctx.udp_manager.get_mut(&self.fd) {
                    handle.incoming.pop_front()
                } else {
                    panic!("SimContext lost socket")
                }
            });

            match r {
                Some((src, _, msg)) => {
                    let wrt = msg.content.len().min(buf.len());
                    for i in 0..wrt {
                        buf[i] = msg.content[i];
                    }

                    return Ok((wrt, src));
                }
                None => {}
            }
        }
    }

    /// Gets the value of the `SO_BROADCAST option for this socket.
    ///
    /// For more information about this option, see [set_broadcast](UdpSocket::set_broadcast)
    pub fn broadcast(&self) -> Result<bool> {
        IOContext::with_current(|ctx| match ctx.udp_manager.get(&self.fd) {
            Some(ref sock) => Ok(sock.broadcast),
            None => Err(Error::new(
                ErrorKind::Other,
                "SimContext lost socket handle",
            )),
        })
    }

    /// Sets the value of the SO_BROADCAST option for this socket.
    ///
    /// When enabled, this socket is allowed to send packets to a broadcast address.
    pub fn set_broadcast(&self, on: bool) -> Result<()> {
        IOContext::with_current(|ctx| match ctx.udp_manager.get_mut(&self.fd) {
            Some(sock) => {
                sock.broadcast = on;
                Ok(())
            }
            None => Err(Error::new(
                ErrorKind::Other,
                "SimContext lost socket handle",
            )),
        })
    }

    /// Gets the value of the IP_TTL option for this socket.
    ///
    /// For more information about this option, see [set_ttl](UdpSocket::set_ttl).
    ///
    pub fn ttl(&self) -> Result<u8> {
        IOContext::with_current(|ctx| match ctx.udp_manager.get(&self.fd) {
            Some(ref sock) => Ok(sock.ttl),
            None => Err(Error::new(
                ErrorKind::Other,
                "SimContext lost socket handle",
            )),
        })
    }

    /// Sets the value for the IP_TTL option on this socket.
    ///
    /// This value sets the time-to-live field that is used in every packet sent from this socket.
    pub fn set_ttl(&self, ttl: u8) -> Result<()> {
        IOContext::with_current(|ctx| match ctx.udp_manager.get_mut(&self.fd) {
            Some(sock) => {
                sock.ttl = ttl;
                Ok(())
            }
            None => Err(Error::new(
                ErrorKind::Other,
                "SimContext lost socket handle",
            )),
        })
    }

    pub fn device(&self) -> Result<Option<InterfaceName>> {
        IOContext::with_current(|ctx| ctx.bsd_socket_device(self.fd))
    }
}

impl Drop for UdpSocket {
    fn drop(&mut self) {
        IOContext::try_with_current(|ctx| ctx.udp_drop(self.fd));
    }
}
