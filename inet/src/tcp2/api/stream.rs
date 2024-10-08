use std::{
    io::{Error, ErrorKind},
    net::SocketAddr,
    sync::Arc,
};

use tokio::io::AsyncWrite;

use crate::{
    dns::{lookup_host, ToSocketAddrs},
    socket::Fd,
    IOContext,
};

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

    pub async fn connect<A: ToSocketAddrs>(addr: A) -> Result<TcpStream, Error> {
        let addrs = lookup_host(addr).await?;
        let last_err = None;

        for peer in addrs {
            let fd = IOContext::with_current(|ctx| ctx.tcp2_connect(peer, None, None))?;

            while let Some(notify) = IOContext::with_current(|ctx| ctx.tcp2_connect_await_estab(fd))
            {
                notify.await;
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
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        std::task::Poll::Ready(Ok(()))
    }
    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        std::task::Poll::Ready(Ok(()))
    }
}
