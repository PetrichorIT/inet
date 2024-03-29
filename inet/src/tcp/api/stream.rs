use crate::io::{Interest, Ready};
use crate::{
    dns::{lookup_host, ToSocketAddrs},
    interface::IfId,
    socket::*,
    socket::*,
    tcp::{
        interest::{TcpInterest, TcpInterestGuard},
        types::{TcpEvent, TcpState, TcpSyscall},
        TcpSocketConfig, TransmissionControlBlock,
    },
    IOContext,
};
use std::{
    io::{Error, ErrorKind, Result},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    stream,
    sync::oneshot,
};

mod owned_half;
pub use owned_half::*;

mod ref_half;
pub use ref_half::*;

/// A TCP Stream.
#[derive(Debug)]
pub struct TcpStream {
    pub(crate) inner: Arc<TcpStreamInner>,
}

#[derive(Debug)]
pub(crate) struct TcpStreamInner {
    pub(crate) fd: Fd,
}

impl TcpStream {
    /// Opens a TCP connection to a remote host.
    ///
    /// addr is an address of the remote host.
    /// Anything which implements the ToSocketAddrs trait can be supplied as the address.
    /// If addr yields multiple addresses, connect will be attempted with each of the addresses
    /// until a connection is successful. If none of the addresses result in a successful connection,
    /// the error returned from the last connection attempt (the last address) is returned.
    pub async fn connect<A: ToSocketAddrs>(addr: A) -> Result<TcpStream> {
        let addrs = lookup_host(addr).await?;
        let mut last_err = None;

        for peer in addrs {
            let this =
                IOContext::with_current(|ctx| ctx.tcp_create_and_connect_socket(peer, None, None))?;

            loop {
                // Initiate connect by sending a message (better repeat)

                let estab =
                    match IOContext::with_current(|ctx| ctx.tcp_await_established(this.inner.fd)) {
                        Ok(estab) => estab,
                        Err(e) => {
                            last_err = Some(e);
                            break;
                        }
                    };

                match estab.await.expect("Did not expect recv error") {
                    Ok(_) => {}
                    Err(e) => {
                        last_err = Some(e);
                        break;
                    }
                }

                if IOContext::with_current(|ctx| ctx.tcp_connected(this.inner.fd))? {
                    return Ok(this);
                }
            }
        }

        Err(last_err.unwrap_or(Error::new(ErrorKind::Other, "No address worked")))
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

    /// Waits for the socket to become writable.
    ///
    /// This function is equivalent to `ready(Interest::WRITABLE)` and
    /// is usually paired with `try_write()`.
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

    /// Splits a `TcpStream` into a read half and a write half, which can be used to read and write the stream concurrently.
    pub fn into_split(self) -> (OwnedReadHalf, OwnedWriteHalf) {
        (
            OwnedReadHalf {
                inner: self.inner.clone(),
            },
            OwnedWriteHalf { inner: self.inner },
        )
    }
}

impl AsyncRead for TcpStream {
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

impl AsyncWrite for TcpStream {
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

impl Drop for TcpStreamInner {
    fn drop(&mut self) {
        IOContext::try_with_current(|ctx| ctx.tcp_drop_stream(self.fd));
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
            inner: Arc::new(TcpStreamInner { fd }),
        }
    }
}

impl IOContext {
    pub(super) fn tcp_create_and_connect_socket(
        &mut self,
        peer: SocketAddr,
        config: Option<TcpSocketConfig>,
        fd: Option<Fd>,
    ) -> Result<TcpStream> {
        let (fd, config) = if let Some(fd) = fd {
            // check whether socket was bound.
            let Some(socket) = self.sockets.get(&fd) else {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    "invalid fd - socket dropped"
                ))
            };

            let socket_bound = socket.interface != SocketIfaceBinding::NotBound;
            if !socket_bound {
                let sock_typ = socket.domain;
                let unspecified = match sock_typ {
                    SocketDomain::AF_INET => {
                        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0)
                    }
                    SocketDomain::AF_INET6 => {
                        SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0)), 0)
                    }
                    _ => unreachable!(),
                };
                self.bind_socket(fd, unspecified)?;
            }

            (fd, config.unwrap())
        } else {
            let domain = if peer.is_ipv4() {
                SocketDomain::AF_INET
            } else {
                SocketDomain::AF_INET6
            };
            let unspecified = if peer.is_ipv4() {
                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0))
            } else {
                SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0))
            };

            let fd = self.create_socket(domain, SocketType::SOCK_STREAM, 0)?;
            let addr = self.bind_socket(fd, unspecified)?;

            let config = config.unwrap_or(self.tcp.config.listener(addr));
            (fd, config)
        };

        self.bind_peer(fd, peer);
        let mut ctrl = TransmissionControlBlock::new(fd, self.get_socket_addr(fd)?, config);
        let span = ctrl.span.clone();
        let _g = span.entered();

        self.process_state_closed(&mut ctrl, TcpEvent::SysOpen(peer));

        self.tcp.streams.insert(fd, ctrl);

        Ok(TcpStream {
            inner: Arc::new(TcpStreamInner { fd }),
        })
    }

    pub fn tcp_await_established(&mut self, fd: Fd) -> Result<oneshot::Receiver<Result<()>>> {
        let Some(tcp) = self.tcp.streams.get_mut(&fd) else {
            return Err(Error::new(ErrorKind::InvalidInput, "invalid fd - socket dropped"))
        };
        let span = tcp.span.clone();
        let _g = span.entered();

        if tcp.syn_resend_counter >= 3 {
            return Err(Error::new(
                ErrorKind::NotFound,
                "host not found - syn exceeded",
            ));
        }

        let (tx, rx) = oneshot::channel();
        assert!(tcp.established.replace(tx).is_none());
        Ok(rx)
    }

    pub(super) fn tcp_connected(&mut self, fd: Fd) -> Result<bool> {
        let Some(tcp) = self.tcp.streams.get(&fd) else {
            return Err(Error::new(ErrorKind::InvalidInput, "invalid fd - socket dropped"))
        };

        if tcp.syn_resend_counter >= 3 {
            return Err(Error::new(
                ErrorKind::NotFound,
                "host not found - syn exceeded",
            ));
        }

        Ok(tcp.state as u8 >= TcpState::Established as u8)
    }

    pub(super) fn tcp_drop_stream(&mut self, fd: Fd) {
        self.tcp_syscall(fd, TcpSyscall::Close());
    }
}
