use crate::tcp::interest::{TcpInterest, TcpInterestGuard};
use crate::IOContext;

use super::super::TcpStreamInner;
use super::TcpStream;

use crate::io::{Interest, Ready};
use std::io::{Error, ErrorKind, IoSlice, IoSliceMut, Result};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::*;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Owned read half of a [TcpStream], created by [into_split](super::TcpStream::into_split).
///
/// Reading from an [OwnedReadHalf] is usually done using the convenience methods
/// found on the [AsyncReadExt](des::tokio::io::AsyncReadExt) trait.
#[derive(Debug)]
pub struct OwnedReadHalf {
    pub(super) inner: Arc<TcpStreamInner>,
}

/// Owned read half of a [TcpStream], created by [into_split](super::TcpStream::into_split).
///
/// Reading from an [OwnedReadHalf] is usually done using the convenience methods
/// found on the [AsyncReadExt](des::tokio::io::AsyncReadExt) trait.
#[derive(Debug)]
pub struct OwnedWriteHalf {
    pub(super) inner: Arc<TcpStreamInner>,
}

/// Error indicating that two halves were
/// not from the same socket, and thus could not be reunited.
#[derive(Debug)]
pub struct ReuniteError(pub OwnedReadHalf, pub OwnedWriteHalf);

impl OwnedReadHalf {
    /// Attempts to put the two halves of a [TcpStream] back together
    /// and recover the original socket.
    /// Succeeds only if the two halves originated from the same call to [into_split](TcpStream::into_split).
    pub fn reunite(self, other: OwnedWriteHalf) -> std::result::Result<TcpStream, ReuniteError> {
        if Arc::ptr_eq(&self.inner, &other.inner) {
            Ok(TcpStream { inner: self.inner })
        } else {
            Err(ReuniteError(self, other))
        }
    }

    /// Receives data on the socket from the remote address to which it is connected,
    /// without removing that data from the queue.
    /// On success, returns the number of bytes peeked.
    ///
    /// Successive calls return the same data.
    /// This is accomplished by passing MSG_PEEK as a flag to the underlying recv system call.
    pub async fn peek(&self, buf: &mut [u8]) -> Result<usize> {
        loop {
            self.readable().await?;

            match IOContext::with_current(|ctx| ctx.tcp_try_peek(self.inner.fd, buf)) {
                Ok(n) => return Ok(n),
                Err(e) if e.kind() == ErrorKind::WouldBlock => continue,
                Err(e) => return Err(e),
            }
        }
    }

    /// Returns the local address that this stream is bound to.
    pub fn local_addr(&self) -> Result<SocketAddr> {
        IOContext::with_current(|ctx| ctx.get_socket_addr(self.inner.fd))
    }

    /// Returns the peer address that this stream is bound to.
    pub fn peer_addr(&self) -> Result<SocketAddr> {
        IOContext::with_current(|ctx| ctx.get_socket_peer(self.inner.fd))
    }

    /// DEPRECATED
    #[deprecated(note = "Cannot create simulated socket from std::net::TcpStream")]
    #[allow(unused)]
    pub fn poll_peek(&self, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<Result<usize>> {
        unimplemented!()
    }

    /// Waits for any of the requested ready states.
    ///
    /// This function is usually paired with try_read() or try_write().
    /// It can be used to concurrently read / write to the same socket on a single task
    /// without splitting the socket.
    pub async fn ready(&self, interest: Interest) -> Result<Ready> {
        let io = TcpInterest::from_tokio(self.inner.fd, interest);
        io.await
    }

    /// Waits for the socket to become readable.
    ///
    /// This function is equivalent to ready(Interest::READABLE) and is usually paired with try_read().
    pub async fn readable(&self) -> Result<()> {
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
    pub fn try_read(&self, buf: &mut [u8]) -> Result<usize> {
        IOContext::with_current(|ctx| ctx.tcp_try_read(self.inner.fd, buf))
    }

    /// DEPRECATED
    #[deprecated(note = "Cannot create simulated socket from std::net::TcpStream")]
    #[allow(unused)]
    pub fn try_read_buf<B>(&self, buf: &mut B) -> Result<usize> {
        unimplemented!()
    }

    /// DEPRECATED
    #[deprecated(note = "Cannot create simulated socket from std::net::TcpStream")]
    #[allow(unused)]
    pub fn try_read_vectored(&self, bufs: &mut [IoSliceMut<'_>]) -> Result<usize> {
        unimplemented!()
    }
}

impl OwnedWriteHalf {
    /// Attempts to put the two halves of a [TcpStream] back together
    /// and recover the original socket.
    /// Succeeds only if the two halves originated from the same call to [into_split](TcpStream::into_split).
    pub fn reunite(self, other: OwnedReadHalf) -> std::result::Result<TcpStream, ReuniteError> {
        if Arc::ptr_eq(&self.inner, &other.inner) {
            Ok(TcpStream { inner: self.inner })
        } else {
            Err(ReuniteError(other, self))
        }
    }

    /// Destroys the write half, but don’t close the write half of the stream until the read half is dropped.
    /// If the read half has already been dropped, this closes the stream.
    pub fn forget(self) {
        drop(self);
    }

    /// Returns the local address that this stream is bound to.
    pub fn local_addr(&self) -> Result<SocketAddr> {
        IOContext::with_current(|ctx| ctx.get_socket_addr(self.inner.fd))
    }

    /// Returns the peer address that this stream is bound to.
    pub fn peer_addr(&self) -> Result<SocketAddr> {
        IOContext::with_current(|ctx| ctx.get_socket_peer(self.inner.fd))
    }

    /// Waits for any of the requested ready states.
    ///
    /// This function is usually paired with try_read() or try_write().
    /// It can be used to concurrently read / write to the same socket on a single task
    /// without splitting the socket.
    pub async fn ready(&self, interest: Interest) -> Result<Ready> {
        let io = TcpInterest::from_tokio(self.inner.fd, interest);
        io.await
    }

    /// Waits for the socket to become writable.
    ///
    /// This function is equivalent to `ready(Interest::WRITABLE)` and is usually paired with `try_write()`.
    pub async fn writable(&self) -> Result<()> {
        self.ready(Interest::WRITABLE).await?;
        Ok(())
    }

    /// Try to write a buffer to the stream, returning how many bytes were written.
    ///
    /// The function will attempt to write the entire contents of `buf`,
    /// but only part of the buffer may be written.
    pub fn try_write(&self, buf: &[u8]) -> Result<usize> {
        IOContext::with_current(|ctx| ctx.tcp_try_write(self.inner.fd, buf))
    }

    /// DEPRECATED
    #[deprecated(note = "Cannot create simulated socket from std::net::TcpStream")]
    #[allow(unused)]
    pub fn try_write_vectored(&self, bufs: &[IoSlice<'_>]) -> Result<usize> {
        unimplemented!()
    }
}

impl AsyncRead for OwnedReadHalf {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<()>> {
        IOContext::with_current(|ctx| {
            match ctx.tcp_try_read(self.inner.fd, buf.initialize_unfilled()) {
                Ok(n) => {
                    buf.advance(n);
                    Poll::Ready(Ok(()))
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => {
                    let Some(handle) = ctx.tcp.streams.get_mut(&self.inner.fd) else {
                        return Poll::Ready(Err(Error::new(
                            ErrorKind::InvalidInput,
                            "socket dropped - invalid fd",
                        )));
                    };
                    handle.rx_read_interests.push(TcpInterestGuard {
                        interest: TcpInterest::TcpRead(self.inner.fd),
                        waker: cx.waker().clone(),
                    });
                    Poll::Pending
                }
                Err(e) => Poll::Ready(Err(e)),
            }
        })
    }
}

impl AsyncWrite for OwnedWriteHalf {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<Result<usize>> {
        IOContext::with_current(|ctx| match ctx.tcp_try_write(self.inner.fd, buf) {
            Ok(n) => Poll::Ready(Ok(n)),
            Err(e) if e.kind() == ErrorKind::WouldBlock => {
                let Some(handle) = ctx.tcp.streams.get_mut(&self.inner.fd) else {
                    return Poll::Ready(Err(Error::new(
                        ErrorKind::InvalidInput,
                        "socket dropped - invalid fd",
                    )));
                };
                handle.tx_write_interests.push(TcpInterestGuard {
                    interest: TcpInterest::TcpRead(self.inner.fd),
                    waker: cx.waker().clone(),
                });
                Poll::Pending
            }
            Err(e) => Poll::Ready(Err(e)),
        })
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        Poll::Ready(Ok(())) // TODO ?
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        Poll::Ready(Ok(())) // TODO ?
    }
}
