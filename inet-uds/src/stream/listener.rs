use inet::types::uds::SocketAddr;
use std::{
    io::{Error, ErrorKind, Result},
    path::Path,
};
use tokio::sync::{
    mpsc::{channel, Receiver, Sender},
    oneshot, Mutex,
};

use crate::UdsExtension;

use super::UnixStream;
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
    pub(super) addr: SocketAddr,
    pub(super) establish: oneshot::Sender<UnixStream>,
}

impl UnixListener {
    pub fn bind<P>(path: P) -> Result<UnixListener>
    where
        P: AsRef<Path>,
    {
        IOContext::with_current(|ctx| ctx.uds_listener_bind(path.as_ref()))
    }

    pub async fn accept(&self) -> Result<(UnixStream, SocketAddr)> {
        let Some(incoming) = self.rx.lock().await.recv().await else {
            return Err(Error::new(ErrorKind::Other, "socket closed"));
        };

        IOContext::with_current(|ctx| ctx.uds_listener_accept(self.fd, incoming))
    }
}

impl Drop for UnixListener {
    fn drop(&mut self) {
        IOContext::try_with_current(|ctx| ctx.uds_listener_drop(self.fd));
    }
}

impl UdsExtension {
    fn uds_listener_bind(&mut self, path: &Path) -> Result<UnixListener> {
        let addr = SocketAddr::from(path.to_path_buf());

        let entry = self.uds.binds.iter().any(|s| s.1.addr == addr);
        if entry {
            return Err(Error::new(ErrorKind::AddrInUse, "address already in use"));
        }

        let fd: Fd = self.create_socket(SocketDomain::AF_UNIX, SocketType::SOCK_STREAM, 1)?;

        let (tx, rx) = channel(16);
        let handle = UnixListenerHandle { tx, addr };
        let socket = UnixListener {
            fd,
            rx: Mutex::new(rx),
        };

        self.uds.binds.insert(fd, handle);
        Ok(socket)
    }

    fn uds_listener_accept(
        &mut self,
        lis_fd: Fd,
        incoming: IncomingStream,
    ) -> Result<(UnixStream, SocketAddr)> {
        let Some(listener) = self.uds.binds.get(&lis_fd) else {
            return Err(Error::new(ErrorKind::Other, "dropped"));
        };
        let l_addr = listener.addr.clone();

        // (0) create new local socket
        let server_fd = self.create_socket(SocketDomain::AF_UNIX, SocketType::SOCK_STREAM, 0)?;

        let (client, server) =
            self.uds_stream_link((incoming.fd, incoming.addr.clone()), (server_fd, l_addr));

        incoming
            .establish
            .send(client)
            .map_err(|_| Error::new(ErrorKind::Other, "failed to establish stream, client died"))?;
        Ok((server, incoming.addr))
    }

    fn uds_listener_drop(&mut self, fd: Fd) -> Result<()> {
        self.uds.binds.remove(&fd);
        self.close_socket(fd)
    }
}
