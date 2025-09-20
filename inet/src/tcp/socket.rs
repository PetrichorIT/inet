use super::{TcpListener, TcpStream};
use crate::IOContext;
use crate::socket::{Fd, SocketDomain, SocketType};
use crate::tcp::interest::TcpInterest;
use crate::tcp::stream::Inner;
use crate::tcp::{Config, State};
use std::cell::{Cell, RefCell};
use std::io::{Error, ErrorKind, Result};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::Arc;
use std::time::Duration;

/// A TCP socket that has not yet been converted to a TcpStream or TcpListener.
#[derive(Debug)]
pub struct TcpSocket {
    fd: Fd,
    addr: Cell<SocketAddr>,
    config: RefCell<Config>,
}

impl TcpSocket {
    /// Creates a new socket configured for IPv4.
    pub fn new_v4() -> Result<TcpSocket> {
        IOContext::with_current(|ctx| {
            Ok(TcpSocket {
                addr: Cell::new(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0))),
                config: RefCell::new(ctx.tcp.config.clone()),
                fd: ctx.socket(SocketDomain::AF_INET, SocketType::SOCK_STREAM, 0)?,
            })
        })
    }

    /// Creates a new socket configured for IPv6.
    pub fn new_v6() -> Result<TcpSocket> {
        IOContext::with_current(|ctx| {
            Ok(TcpSocket {
                addr: Cell::new(SocketAddr::V6(SocketAddrV6::new(
                    Ipv6Addr::UNSPECIFIED,
                    0,
                    0,
                    0,
                ))),
                config: RefCell::new(ctx.tcp.config.clone()),
                fd: ctx.socket(SocketDomain::AF_INET6, SocketType::SOCK_STREAM, 0)?,
            })
        })
    }

    /// Sets the inital sequence number.
    pub fn set_maximum_segement_size(&self, mss: u16) -> Result<()> {
        self.config.borrow_mut().mss = Some(mss);
        Ok(())
    }

    /// Gets the inital sequence number.
    pub fn maximum_segement_size(&self) -> Result<u16> {
        Ok(self.config.borrow().mss.unwrap_or(0))
    }

    /// Sets the inital sequence number.
    pub fn set_inital_seq_no(&self, iss: u32) -> Result<()> {
        self.config.borrow_mut().iss = Some(iss);
        Ok(())
    }

    /// Gets the inital sequence number.
    pub fn inital_seq_no(&self) -> Result<u32> {
        Ok(self.config.borrow().iss.unwrap_or(0))
    }

    /// Allows the socket to bind to an in-use address.
    ///
    /// Behavior is platform specific.
    /// Refer to the target platform’s documentation for more details.
    pub fn set_reuseaddr(&self, reuseaddr: bool) -> Result<()> {
        self.config.borrow_mut().reuseaddr = reuseaddr;
        Ok(())
    }

    /// Retrieves the value set for SO_REUSEADDR on this socket.
    pub fn reuseaddr(&self) -> Result<bool> {
        Ok(self.config.borrow().reuseaddr)
    }

    /// Allows the socket to bind to an in-use port.
    /// Only available for unix systems (excluding Solaris & Illumos).
    ///
    /// Behavior is platform specific. Refer to the target platform’s documentation for more details.
    pub fn set_reuseport(&self, reuseport: bool) -> Result<()> {
        self.config.borrow_mut().reuseport = reuseport;
        Ok(())
    }

    /// Allows the socket to bind to an in-use port.
    /// Only available for unix systems (excluding Solaris & Illumos).
    ///
    /// Behavior is platform specific. Refer to the target platform’s documentation for more details.
    pub fn reuseport(&self) -> Result<bool> {
        Ok(self.config.borrow().reuseport)
    }

    /// Sets the size of the TCP send buffer on this socket.
    ///
    /// On most operating systems, this sets the SO_SNDBUF socket option.
    pub fn set_send_buffer_size(&self, size: usize) -> Result<()> {
        self.config.borrow_mut().send_buffer_cap = size;
        Ok(())
    }

    /// Returns the size of the TCP send buffer for this socket.
    ///
    /// On most operating systems, this is the value of the SO_SNDBUF socket option.
    pub fn send_buffer_size(&self) -> Result<usize> {
        Ok(self.config.borrow().send_buffer_cap)
    }

    /// Sets the size of the TCP receive buffer on this socket.
    ///
    /// On most operating systems, this sets the SO_RCVBUF socket option.
    pub fn set_recv_buffer_size(&self, size: usize) -> Result<()> {
        self.config.borrow_mut().recv_buffer_cap = size;
        Ok(())
    }

    /// Returns the size of the TCP receive buffer for this socket.
    ///
    /// On most operating systems, this is the value of the SO_RCVBUF socket option.
    pub fn recv_buffer_size(&self) -> Result<usize> {
        Ok(self.config.borrow().recv_buffer_cap)
    }

    /// Sets the linger duration of this socket by setting the SO_LINGER option.
    ///
    /// This option controls the action taken when a stream has unsent messages
    /// and the stream is closed. If SO_LINGER is set, the system shall block the process
    /// until it can transmit the data or until the time expires.
    ///
    /// If SO_LINGER is not specified, and the socket is closed, the system handles the call
    /// in a way that allows the process to continue as quickly as possible.
    pub fn set_linger(&self, dur: Option<Duration>) -> Result<()> {
        self.config.borrow_mut().linger = dur;
        Ok(())
    }

    /// Reads the linger duration for this socket by getting the SO_LINGER option.
    ///
    /// For more information about this option, see [set_linger](TcpSocket::set_linger).
    pub fn linger(&self) -> Result<Option<Duration>> {
        Ok(self.config.borrow().linger)
    }

    // Gets the local address of this socket.
    ///
    /// Will fail on windows if called before bind
    pub fn local_addr(&self) -> Result<SocketAddr> {
        IOContext::with_current(|ctx| ctx.socket_get_addr(self.fd))
    }

    /// Returns the value of the SO_ERROR option.
    pub fn take_error(&self) -> Result<Option<Error>> {
        Ok(None)
    }

    /// Binds the socket to the given address.
    ///
    /// This calls the bind(2) operating-system function.
    /// Behavior is platform specific. Refer to the target platform’s documentation for more details.
    pub fn bind(&self, addr: SocketAddr) -> Result<()> {
        if self.addr.get().is_ipv4() != addr.ip().is_ipv4() {
            return Err(Error::new(ErrorKind::Other, "Expected other ip typ"));
        }

        let addr = IOContext::with_current(|ctx| ctx.socket_bind(self.fd, addr))?;
        self.addr.set(addr);
        Ok(())
    }

    /// Establishes a TCP connection with a peer at the specified socket address.
    ///
    /// The TcpSocket is consumed. Once the connection is established,
    /// a connected TcpStream is returned.
    /// If the connection fails, the encountered error is returned.
    ///
    /// This calls the connect(2) operating-system function.
    /// Behavior is platform specific.
    /// Refer to the target platform’s documentation for more details.
    pub async fn connect(mut self, peer: SocketAddr) -> Result<TcpStream> {
        let fd = self.fd;
        self.fd = 0;
        let fd = IOContext::with_current(|ctx| {
            ctx.tcp_connect(peer, Some(self.config.borrow().clone()), Some(fd))
        })?;

        if IOContext::with_current(|ctx| ctx.tcp_connection(fd, |c| c.state != State::Estab))? {
            let interest = TcpInterest::write(fd);
            return interest
                .await
                .map_err(|e| {
                    let _ = IOContext::with_current(|ctx| ctx.tcp_drop(fd));
                    e
                })
                .map(|_| TcpStream {
                    inner: Arc::new(Inner { fd }),
                });
        }

        Err(Error::new(ErrorKind::Other, "No address worked"))
    }

    /// Converts the socket into a TcpListener.
    ///
    /// backlog defines the maximum number of pending connections
    /// are queued by the operating system at any given time.
    /// Connection are removed from the queue with TcpListener::accept.
    /// When the queue is full, the operating-system will start rejecting connections.
    ///
    /// This calls the listen(2) operating-system function, marking the socket as a
    /// passive socket. Behavior is platform specific.
    /// Refer to the target platform’s documentation for more details.
    pub fn listen(mut self, backlog: u32) -> Result<TcpListener> {
        let local_addr = self.local_addr()?;

        let fd = Some(self.fd);
        self.fd = 0;
        IOContext::with_current(move |ctx| {
            ctx.tcp_bind(
                local_addr,
                Some(self.config.borrow().clone()),
                fd,
                Some(backlog as usize),
            )
        })
    }

    /// DEPRECATED
    #[deprecated(note = "Not implemented in simulation context")]
    #[allow(unused)]
    pub fn from_std_stream(std_stream: std::net::TcpStream) -> TcpSocket {
        unimplemented!()
    }
}

impl Drop for TcpSocket {
    fn drop(&mut self) {
        if self.fd != 0 {
            IOContext::try_with_current(|ctx| ctx.socket_close(self.fd));
        }
    }
}
