use types::uds::SocketAddr;
use std::{
    future::Future,
    io::{Error, ErrorKind, Result},
    path::Path,
    pin::Pin,
    sync::{self, Arc},
    task::{Context, Poll, Waker},
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    pin,
    sync::{oneshot, Mutex},
};

use super::{buf::Buffer, listener::IncomingStream};
use crate::socket::Fd;
use crate::{
    ctx::IOContext,
    socket::{SocketDomain, SocketType},
};

/// A stream-oriented unix domain socket.
#[derive(Debug)]
pub struct UnixStream {
    pub(super) fd: Fd,
    pub(super) addr: SocketAddr,
    pub(super) peer: SocketAddr,

    pub(super) rx_buf: Arc<Mutex<Buffer>>,
    pub(super) rx_readable: Arc<sync::Mutex<Option<Waker>>>,
    pub(super) rx_writable: Arc<sync::Mutex<Option<Waker>>>,

    pub(super) tx_buf: Arc<Mutex<Buffer>>,
    pub(super) tx_readable: Arc<sync::Mutex<Option<Waker>>>,
    pub(super) tx_writable: Arc<sync::Mutex<Option<Waker>>>,
}

impl UnixStream {
    pub async fn connect<P>(path: P) -> Result<UnixStream>
    where
        P: AsRef<Path>,
    {
        let estab =
            IOContext::with_current(|ctx: &mut IOContext| ctx.uds_stream_connect(path.as_ref()))?;
        estab.await.map_err(|e| Error::new(ErrorKind::Other, e))
    }

    pub fn pair() -> Result<(UnixStream, UnixStream)> {
        IOContext::with_current(|ctx: &mut IOContext| ctx.uds_stream_pair())
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.addr.clone())
    }

    pub fn peer_addr(&self) -> Result<SocketAddr> {
        Ok(self.peer.clone())
    }
}

impl AsyncRead for UnixStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<Result<()>> {
        let lock = self.rx_buf.lock();
        pin!(lock);

        let mut lock = match lock.poll(cx) {
            Poll::Ready(lock) => lock,
            Poll::Pending => todo!(),
        };

        // read from buf
        let n = lock.read(buf.initialize_unfilled());
        buf.advance(n);

        if n == 0 {
            if Arc::strong_count(&self.rx_buf) == 1 {
                // sender is dead

                Poll::Ready(Ok(()))
            } else {
                // pending
                *self.rx_readable.lock().unwrap() = Some(cx.waker().clone());
                Poll::Pending
            }
        } else {
            self.rx_writable.lock().unwrap().take().map(|w| w.wake());
            Poll::Ready(Ok(()))
        }
    }
}

impl AsyncWrite for UnixStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<Result<usize>> {
        let lock = self.tx_buf.lock();
        pin!(lock);
        let mut lock = match lock.poll(cx) {
            Poll::Ready(lock) => lock,
            Poll::Pending => todo!(),
        };

        // write to buf
        let n = lock.write(buf);

        if n == 0 {
            if Arc::strong_count(&self.tx_buf) == 1 {
                // sender is dead

                Poll::Ready(Ok(0))
            } else {
                // pending

                *self.tx_writable.lock().unwrap() = Some(cx.waker().clone());
                Poll::Pending
            }
        } else {
            self.tx_readable.lock().unwrap().take().map(|w| w.wake());
            Poll::Ready(Ok(n))
        }
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<std::result::Result<(), std::io::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<std::result::Result<(), std::io::Error>> {
        Poll::Ready(Ok(()))
    }
}

impl Drop for UnixStream {
    fn drop(&mut self) {
        self.tx_readable.lock().unwrap().take().map(|w| w.wake());
        self.rx_writable.lock().unwrap().take().map(|w| w.wake());
        IOContext::try_with_current(|ctx| ctx.uds_stream_drop(self.fd));
    }
}

impl IOContext {
    fn uds_stream_connect(&mut self, path: &Path) -> Result<oneshot::Receiver<UnixStream>> {
        let addr = SocketAddr::from(path.to_path_buf());

        let fd: Fd = self.create_socket(SocketDomain::AF_UNIX, SocketType::SOCK_STREAM, 0)?;

        let Some(lis) = self.uds.binds.iter().find(|s| s.1.addr == addr) else {
            return Err(Error::new(ErrorKind::ConnectionRefused, "connection refused"));
        };

        let (tx, rx) = oneshot::channel();

        let incoming = IncomingStream {
            fd,
            addr: SocketAddr::unnamed(),
            establish: tx,
        };
        lis.1
            .tx
            .try_send(incoming)
            .map_err(|e| Error::new(ErrorKind::Other, e))?;
        Ok(rx)
    }

    fn uds_stream_pair(&mut self) -> Result<(UnixStream, UnixStream)> {
        let client = self.create_socket(SocketDomain::AF_UNIX, SocketType::SOCK_STREAM, 0)?;
        let server = self.create_socket(SocketDomain::AF_UNIX, SocketType::SOCK_STREAM, 0)?;

        Ok(self.uds_stream_link(
            (client, SocketAddr::unnamed()),
            (server, SocketAddr::unnamed()),
        ))
    }

    pub(super) fn uds_stream_link(
        &mut self,
        client: (Fd, SocketAddr),
        server: (Fd, SocketAddr),
    ) -> (UnixStream, UnixStream) {
        // (1) create server socket
        let server_buf = Arc::new(Mutex::new(Buffer::new(4096)));
        let server_buf_readable = Arc::new(sync::Mutex::new(None));
        let server_buf_writable = Arc::new(sync::Mutex::new(None));

        let client_buf = Arc::new(Mutex::new(Buffer::new(4096)));
        let client_buf_readable = Arc::new(sync::Mutex::new(None));
        let client_buf_writable = Arc::new(sync::Mutex::new(None));

        let server_stream = UnixStream {
            fd: server.0,
            addr: server.1.clone(),
            peer: client.1.clone(),

            rx_buf: server_buf.clone(),
            rx_readable: server_buf_readable.clone(),
            rx_writable: server_buf_writable.clone(),

            tx_buf: client_buf.clone(),
            tx_readable: client_buf_readable.clone(),
            tx_writable: client_buf_writable.clone(),
        };

        let client_stream = UnixStream {
            fd: client.0,
            addr: client.1,
            peer: server.1,

            rx_buf: client_buf,
            rx_readable: client_buf_readable,
            rx_writable: client_buf_writable,

            tx_buf: server_buf,
            tx_readable: server_buf_readable,
            tx_writable: server_buf_writable,
        };

        (client_stream, server_stream)
    }

    fn uds_stream_drop(&mut self, fd: Fd) -> Result<()> {
        self.close_socket(fd)
    }
}
