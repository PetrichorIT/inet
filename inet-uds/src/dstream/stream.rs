use bytes_io::{Buf, BufMut, BytesMut};
use inet::{
    extensions::with_ext,
    socket::{close, socket},
};
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
    sync::{Mutex, oneshot},
};

use crate::{UdsExtension, addr::SocketAddr};

use super::{establish_link, listener::IncomingStream};
use inet::socket::Fd;
use inet::socket::{SocketDomain, SocketType};

/// A stream-oriented unix domain socket.
#[derive(Debug)]
pub struct UnixStream {
    pub(super) fd: Fd,
    pub(super) addr: SocketAddr,
    pub(super) peer: SocketAddr,

    pub(super) rx_buf: Arc<Mutex<BytesMut>>,
    pub(super) rx_readable: Arc<sync::Mutex<Option<Waker>>>,
    pub(super) rx_writable: Arc<sync::Mutex<Option<Waker>>>,

    pub(super) tx_buf: Arc<Mutex<BytesMut>>,
    pub(super) tx_readable: Arc<sync::Mutex<Option<Waker>>>,
    pub(super) tx_writable: Arc<sync::Mutex<Option<Waker>>>,
}

impl UnixStream {
    pub async fn connect<P>(path: P) -> Result<UnixStream>
    where
        P: AsRef<Path>,
    {
        let socket = socket(SocketDomain::AF_UNIX, SocketType::SOCK_STREAM, 0)?;
        let rx = with_ext::<UdsExtension, _>(|uds| {
            let addr = SocketAddr::from(path.as_ref().to_path_buf());
            let Some(listener) = uds.listeners.values().find(|s| s.addr == addr) else {
                return Err(Error::new(
                    ErrorKind::ConnectionRefused,
                    "connection refused",
                ));
            };

            let (tx, rx) = oneshot::channel();
            let stream = IncomingStream {
                fd: socket,
                remote_addr: SocketAddr::unnamed(),
                local_addr: listener.addr.clone(),
                establish: tx,
            };

            listener
                .tx
                .try_send(stream)
                .expect("failed to send to socket");

            Ok(rx)
        })?;

        rx.await.map_err(|_| Error::other("onshot failure"))
    }

    pub fn pair() -> Result<(UnixStream, UnixStream)> {
        let lhs = socket(SocketDomain::AF_UNIX, SocketType::SOCK_STREAM, 0)?;
        let rhs = socket(SocketDomain::AF_UNIX, SocketType::SOCK_STREAM, 0)?;

        Ok(establish_link(
            (lhs, SocketAddr::unnamed()),
            (rhs, SocketAddr::unnamed()),
        ))
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
        let n = lock.remaining().min(buf.initialized_mut().len());
        lock.copy_to_slice(&mut buf.initialize_unfilled()[..n]);
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
            if let Some(w) = self.rx_writable.lock().unwrap().take() {
                w.wake()
            }
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

        let n = lock.remaining_mut().min(buf.len());
        lock.put_slice(&buf[..n]);

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
            if let Some(w) = self.tx_readable.lock().unwrap().take() {
                w.wake()
            }
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
        if let Some(w) = self.tx_readable.lock().unwrap().take() {
            w.wake()
        }
        if let Some(w) = self.rx_writable.lock().unwrap().take() {
            w.wake()
        }

        let _ = close(self.fd);
    }
}
