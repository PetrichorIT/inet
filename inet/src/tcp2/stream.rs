use std::{
    io::{Error, ErrorKind},
    net::SocketAddr,
    sync::Arc,
    time::Duration,
};

use crate::io::{Interest, Ready};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::{
    dns::{lookup_host, ToSocketAddrs},
    socket::{AsRawFd, Fd, FromRawFd, IntoRawFd},
    IOContext,
};

use super::{interest, State};

/// A TCP Stream.
#[derive(Debug)]
pub struct TcpStream {
    pub(in crate::tcp2) inner: Arc<Inner>,
}

#[derive(Debug)]
pub(in crate::tcp2) struct Inner {
    pub fd: Fd,
}

impl TcpStream {
    pub(crate) fn from_fd(fd: Fd) -> Self {
        Self {
            inner: Arc::new(Inner { fd }),
        }
    }

    /// Opens a TCP connection to a remote host.
    ///
    /// addr is an address of the remote host.
    /// Anything which implements the ToSocketAddrs trait can be supplied as the address.
    /// If addr yields multiple addresses, connect will be attempted with each of the addresses
    /// until a connection is successful. If none of the addresses result in a successful connection,
    /// the error returned from the last connection attempt (the last address) is returned.
    pub async fn connect<A: ToSocketAddrs>(addr: A) -> Result<TcpStream, Error> {
        let addrs = lookup_host(addr).await?;
        let last_err = None;

        for peer in addrs {
            let fd = IOContext::with_current(|ctx| ctx.tcp2_connect(peer, None, None))?;

            while !IOContext::with_current(|ctx| {
                ctx.tcp2_connection(fd, |c| c.state == State::Estab)
            })? {
                let interest = interest::TcpInterest::Write(fd);
                interest.await.map_err(|e| {
                    let _ = IOContext::with_current(|ctx| ctx.tcp2_drop(fd));
                    e
                })?;
            }

            return Ok(TcpStream {
                inner: Arc::new(Inner { fd }),
            });
        }

        Err(last_err.unwrap_or(Error::new(ErrorKind::Other, "No address worked")))
    }

    /// Returns the local address that this stream is bound to.
    pub fn local_addr(&self) -> Result<SocketAddr, Error> {
        IOContext::with_current(|ctx| ctx.get_socket_addr(self.inner.fd))
    }

    /// Returns the peer address that this stream is bound to.
    pub fn peer_addr(&self) -> Result<SocketAddr, Error> {
        IOContext::with_current(|ctx| ctx.get_socket_peer(self.inner.fd))
    }

    /// Waits for any of the requested ready states.
    ///
    /// This function is usually paired with try_read() or try_write().
    /// It can be used to concurrently read / write to the same socket on a single task
    /// without splitting the socket.
    pub async fn ready(&self, interest: Interest) -> Result<Ready, Error> {
        let interest = interest::TcpInterest::from_tokio(self.inner.fd, interest);
        interest.await
    }

    /// Waits for the socket to become readable.
    ///
    /// This function is equivalent to ready(Interest::READABLE) and is usually paired with try_read().
    pub async fn readable(&self) -> Result<(), Error> {
        self.ready(Interest::READABLE).await?;
        Ok(())
    }

    /// Tries to read data from the stream into the provided buffer,
    /// returning how many bytes were read.
    ///
    /// Receives any pending data from the socket but does not wait for new data to arrive.
    /// On success, returns the number of bytes read.
    /// Because try_read() is non-blocking, the buffer does not have to be stored by the async task
    /// and can exist entirely on the stack.
    pub fn try_read(&self, buf: &mut [u8]) -> Result<usize, Error> {
        IOContext::with_current(|ctx| ctx.tcp2_connection(self.inner.fd, |con| con.read(buf)))?
    }

    /// Receives data on the socket from the remote address to which it is connected,
    /// without removing that data from the queue.
    /// On success, returns the number of bytes peeked.
    ///
    /// Successive calls return the same data.
    /// This is accomplished by passing MSG_PEEK as a flag to the underlying recv system call.
    pub async fn peek(&self, buf: &mut [u8]) -> Result<usize, Error> {
        loop {
            self.readable().await?;

            match IOContext::with_current(|ctx| {
                ctx.tcp2_connection(self.inner.fd, |con| con.peek(buf))
            })? {
                Ok(n) => return Ok(n),
                Err(e) if e.kind() == ErrorKind::WouldBlock => continue,
                Err(e) => return Err(e),
            }
        }
    }

    /// Waits for the socket to become writable.
    ///
    /// This function is equivalent to `ready(Interest::WRITABLE)` and
    /// is usually paired with `try_write()`.
    pub async fn writable(&self) -> Result<(), Error> {
        self.ready(Interest::WRITABLE).await?;
        Ok(())
    }

    /// Try to write a buffer to the stream, returning how many bytes were written.
    ///
    /// The function will attempt to write the entire contents of `buf`,
    /// but only part of the buffer may be written.
    pub fn try_write(&self, buf: &[u8]) -> Result<usize, Error> {
        IOContext::with_current(|ctx| ctx.tcp2_connection(self.inner.fd, |con| con.write(buf)))?
    }

    /// Reads the linger duration for this socket by getting the `SO_LINGER`
    /// option.
    ///
    /// For more information about this option, see [`set_linger`].
    ///
    /// [`set_linger`]: TcpStream::set_linger
    ///
    pub fn linger(&self) -> Result<Option<Duration>, Error> {
        IOContext::with_current(|ctx| ctx.tcp2_connection(self.inner.fd, |con| con.cfg.linger))
    }

    /// Sets the linger duration of this socket by setting the `SO_LINGER` option.
    ///
    /// This option controls the action taken when a stream has unsent messages and the stream is
    /// closed. If `SO_LINGER` is set, the system shall block the process until it can transmit the
    /// data or until the time expires.
    ///
    /// If `SO_LINGER` is not specified, and the stream is closed, the system handles the call in a
    /// way that allows the process to continue as quickly as possible.
    ///
    pub fn set_linger(&self, dur: Option<Duration>) -> Result<(), Error> {
        IOContext::with_current(|ctx| {
            ctx.tcp2_connection(self.inner.fd, |con| con.cfg.linger = dur)
        })
    }

    /// Gets the value of the `IP_TTL` option for this socket.
    ///
    /// For more information about this option, see [`set_ttl`].
    ///
    /// [`set_ttl`]: TcpStream::set_ttl
    pub fn ttl(&self) -> Result<u32, Error> {
        IOContext::with_current(|ctx| ctx.tcp2_connection(self.inner.fd, |con| con.cfg.ttl as u32))
    }

    /// Sets the value for the `IP_TTL` option on this socket.
    ///
    /// This value sets the time-to-live field that is used in every packet sent
    /// from this socket.
    ///
    pub fn set_ttl(&self, ttl: u32) -> Result<(), Error> {
        let ttl = u8::try_from(ttl).expect("invalid ttl value");
        IOContext::with_current(|ctx| ctx.tcp2_connection(self.inner.fd, |con| con.cfg.ttl = ttl))
    }
}

impl AsyncRead for TcpStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        IOContext::with_current(|ctx| {
            ctx.tcp2_read(self.inner.fd, cx, buf)
                .map(|rdy| rdy.map(|n| buf.advance(n)))
        })
    }
}

impl AsyncWrite for TcpStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        IOContext::with_current(|ctx| ctx.tcp2_write(self.inner.fd, cx, buf))
    }
    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        IOContext::with_current(|ctx| ctx.tcp2_flush(self.inner.fd, cx))
    }
    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        std::task::Poll::Ready(Ok(()))
    }
}

impl AsRawFd for TcpStream {
    fn as_raw_fd(&self) -> Fd {
        self.inner.fd
    }
}

impl IntoRawFd for TcpStream {
    fn into_raw_fd(self) -> Fd {
        let fd = self.inner.fd;
        std::mem::forget(self);
        fd
    }
}

impl FromRawFd for TcpStream {
    fn from_raw_fd(fd: Fd) -> TcpStream {
        TcpStream {
            inner: Arc::new(Inner { fd }),
        }
    }
}

impl Drop for Inner {
    fn drop(&mut self) {
        IOContext::try_with_current(|ctx| ctx.tcp2_close(self.fd));
    }
}
