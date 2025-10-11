use super::TcpStream;
use crate::io::{Interest, Ready};
use crate::tcp::interest::TcpInterest;
use std::io::{Error, ErrorKind, IoSlice, IoSliceMut};
use std::net::SocketAddr;
use std::task::*;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Owned read half of a [TcpStream], created by [into_split](super::TcpStream::into_split).
///
/// Reading from an [ReadHalf] is usually done using the convenience methods
/// found on the [AsyncReadExt](tokio::io::AsyncReadExt) trait.
#[derive(Debug)]
pub struct ReadHalf<'a> {
    pub(super) stream: &'a TcpStream,
}

/// Owned read half of a [TcpStream], created by [into_split](super::TcpStream::into_split).
///
/// Reading from an [WriteHalf] is usually done using the convenience methods
/// found on the [AsyncReadExt](tokio::io::AsyncReadExt) trait.
#[derive(Debug)]
pub struct WriteHalf<'a> {
    pub(super) stream: &'a TcpStream,
}

impl ReadHalf<'_> {
    /// Receives data on the socket from the remote address to which it is connected,
    /// without removing that data from the queue.
    /// On success, returns the number of bytes peeked.
    ///
    /// Successive calls return the same data.
    /// This is accomplished by passing MSG_PEEK as a flag to the underlying recv system call.
    pub async fn peek(&self, buf: &mut [u8]) -> Result<usize, Error> {
        loop {
            self.readable().await?;

            match self
                .stream
                .inner
                .handle
                .do_io(|ctx| ctx.tcp_peek(self.stream.inner.fd, buf))
            {
                Ok(n) => return Ok(n),
                Err(e) if e.kind() == ErrorKind::WouldBlock => continue,
                Err(e) => return Err(e),
            }
        }
    }

    /// Returns the local address that this stream is bound to.
    pub fn local_addr(&self) -> Result<SocketAddr, Error> {
        self.stream
            .inner
            .handle
            .do_io(|ctx| ctx.socket_get_addr(self.stream.inner.fd))
    }

    /// Returns the peer address that this stream is bound to.
    pub fn peer_addr(&self) -> Result<SocketAddr, Error> {
        self.stream
            .inner
            .handle
            .do_io(|ctx| ctx.socket_get_peer(self.stream.inner.fd))
    }

    /// Polled peek
    pub fn poll_peek(
        &self,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<usize, Error>> {
        self.stream
            .inner
            .handle
            .do_io(|ctx| ctx.tcp_poll_peek(self.stream.inner.fd, cx, buf))
    }

    /// Waits for any of the requested ready states.
    ///
    /// This function is usually paired with try_read() or try_write().
    /// It can be used to concurrently read / write to the same socket on a single task
    /// without splitting the socket.
    pub async fn ready(&self, interest: Interest) -> Result<Ready, Error> {
        let io = TcpInterest::from_io(
            self.stream.inner.fd,
            interest,
            self.stream.inner.handle.clone(),
        );
        io.await
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
        self.stream
            .inner
            .handle
            .do_io(|ctx| ctx.tcp_read(self.stream.inner.fd, buf))
    }

    /// DEPRECATED
    #[deprecated(note = "Cannot create simulated socket from std::net::TcpStream")]
    #[allow(unused)]
    pub fn try_read_buf<B>(&self, buf: &mut B) -> Result<usize, Error> {
        unimplemented!()
    }

    /// Read vectored
    pub fn try_read_vectored(&self, bufs: &mut [IoSliceMut<'_>]) -> Result<usize, Error> {
        let mut n = 0;
        for buf in bufs {
            n += match self.try_read(buf) {
                Ok(n) => n,
                Err(e) if e.kind() == ErrorKind::WouldBlock && n > 0 => break,
                Err(e) => return Err(e),
            };
        }
        Ok(n)
    }
}

impl WriteHalf<'_> {
    /// Destroys the write half, but don’t close the write half of the stream until the read half is dropped.
    /// If the read half has already been dropped, this closes the stream.
    pub fn forget(self) {
        let _ = self;
    }

    /// Returns the local address that this stream is bound to.
    pub fn local_addr(&self) -> Result<SocketAddr, Error> {
        self.stream
            .inner
            .handle
            .do_io(|ctx| ctx.socket_get_addr(self.stream.inner.fd))
    }

    /// Returns the peer address that this stream is bound to.
    pub fn peer_addr(&self) -> Result<SocketAddr, Error> {
        self.stream
            .inner
            .handle
            .do_io(|ctx| ctx.socket_get_peer(self.stream.inner.fd))
    }

    /// Waits for any of the requested ready states.
    ///
    /// This function is usually paired with try_read() or try_write().
    /// It can be used to concurrently read / write to the same socket on a single task
    /// without splitting the socket.
    pub async fn ready(&self, interest: Interest) -> Result<Ready, Error> {
        let io = TcpInterest::from_io(
            self.stream.inner.fd,
            interest,
            self.stream.inner.handle.clone(),
        );
        io.await
    }

    /// Waits for the socket to become writable.
    ///
    /// This function is equivalent to `ready(Interest::WRITABLE)` and is usually paired with `try_write()`.
    pub async fn writable(&self) -> Result<(), Error> {
        self.ready(Interest::WRITABLE).await?;
        Ok(())
    }

    /// Try to write a buffer to the stream, returning how many bytes were written.
    ///
    /// The function will attempt to write the entire contents of `buf`,
    /// but only part of the buffer may be written.
    pub fn try_write(&self, buf: &[u8]) -> Result<usize, Error> {
        self.stream
            .inner
            .handle
            .do_io(|ctx| ctx.tcp_write(self.stream.inner.fd, buf))
    }

    /// Write vectored
    pub fn try_write_vectored(&self, bufs: &[IoSlice<'_>]) -> Result<usize, Error> {
        let mut n = 0;
        for buf in bufs {
            n += match self.try_write(buf) {
                Ok(n) => n,
                Err(e) if e.kind() == ErrorKind::WouldBlock && n > 0 => {
                    break;
                }
                Err(e) => return Err(e),
            };
        }
        Ok(n)
    }
}

impl AsRef<TcpStream> for ReadHalf<'_> {
    fn as_ref(&self) -> &TcpStream {
        self.stream
    }
}

impl AsRef<TcpStream> for WriteHalf<'_> {
    fn as_ref(&self) -> &TcpStream {
        self.stream
    }
}

impl AsyncRead for ReadHalf<'_> {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        self.stream.inner.handle.do_io(|ctx| {
            ctx.tcp_poll_read(self.stream.inner.fd, cx, buf)
                .map(|rdy| rdy.map(|n| buf.advance(n)))
        })
    }
}

impl AsyncWrite for WriteHalf<'_> {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, Error>> {
        self.stream
            .inner
            .handle
            .do_io(|ctx| ctx.tcp_poll_write(self.stream.inner.fd, cx, buf))
    }
    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        self.stream
            .inner
            .handle
            .do_io(|ctx| ctx.tcp_flush(self.stream.inner.fd, cx))
    }
    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        std::task::Poll::Ready(Ok(()))
    }
}
