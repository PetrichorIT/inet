use inet::{
    extensions::{try_with_ext, with_ext},
    socket::{close, socket},
};
use std::{
    io::{Error, ErrorKind, Result},
    path::Path,
    sync::{self, Arc},
};
use tokio::sync::{
    mpsc::{channel, Receiver, Sender},
    oneshot, Mutex,
};

use crate::{SocketAddr, UdsExtension};

use super::{buf::Buffer, UnixStream};
use inet::socket::Fd;
use inet::socket::{SocketDomain, SocketType};

/// A listener for stream-oriented unix domain socket connections.
#[derive(Debug)]
pub struct UnixListener {
    pub(super) fd: Fd,
    pub(super) rx: Mutex<Receiver<IncomingStream>>,
}

#[derive(Debug)]
pub(crate) struct UnixListenerHandle {
    pub(super) addr: SocketAddr,
    pub(super) tx: Sender<IncomingStream>,
}

#[derive(Debug)]
pub(crate) struct IncomingStream {
    pub(super) fd: Fd,
    pub(super) local_addr: SocketAddr,
    pub(super) remote_addr: SocketAddr,
    pub(super) establish: oneshot::Sender<UnixStream>,
}

impl UnixListener {
    pub fn bind<P>(path: P) -> Result<UnixListener>
    where
        P: AsRef<Path>,
    {
        let fd = socket(SocketDomain::AF_UNIX, SocketType::SOCK_STREAM, 0)?;

        with_ext::<UdsExtension, _>(|uds| {
            let addr = SocketAddr::from(path.as_ref().to_path_buf());
            if uds.listeners.values().any(|v| v.addr == addr) {
                return Err(Error::new(ErrorKind::AddrInUse, "address already in use"));
            }

            let (tx, rx) = channel(8);
            let handle = UnixListenerHandle { addr, tx };
            let listener = UnixListener {
                fd,
                rx: Mutex::new(rx),
            };
            uds.listeners.insert(fd, handle);
            Ok(listener)
        })
    }

    pub async fn accept(&self) -> Result<(UnixStream, SocketAddr)> {
        let Some(incoming) = self.rx.lock().await.recv().await else {
            return Err(Error::new(ErrorKind::Other, "socket closed"));
        };

        let fd = socket(SocketDomain::AF_UNIX, SocketType::SOCK_STREAM, 0)?;
        let (client, server) = establish_link(
            (incoming.fd, incoming.remote_addr.clone()),
            (fd, incoming.local_addr),
        );

        incoming
            .establish
            .send(client)
            .map_err(|_| Error::new(ErrorKind::Other, "failed to establish con"))?;

        Ok((server, incoming.remote_addr))
    }
}

impl Drop for UnixListener {
    fn drop(&mut self) {
        let _ = close(self.fd);
        let _ = try_with_ext::<UdsExtension, _>(|uds| uds.listeners.remove(&self.fd));
    }
}

pub(super) fn establish_link(
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
