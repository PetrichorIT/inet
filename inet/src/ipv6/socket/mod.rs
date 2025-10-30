use std::{
    io::{self, Error, ErrorKind},
    net::{IpAddr, Ipv6Addr, SocketAddr},
    task::{Poll, Waker},
};

use bytes_io::Bytes;
use tokio::sync::mpsc::{Receiver, Sender, channel, error::TryRecvError};
use types::{icmpv6::IcmpV6Packet, ip::Ipv6Packet};

use crate::{
    IOHandle,
    ctx::IOContext,
    dns::{ToSocketAddrs, lookup_host},
    interface::IfId,
    ioctx,
    socket::{Fd, SocketDomain, SocketType},
};

#[cfg(test)]
mod tests;

#[derive(Debug)]
pub struct RawV6Socket {
    handle: IOHandle,
    rx: Receiver<Envelope>,
    cfg: Config,
    fd: Fd,
}

#[derive(Debug)]
struct Config {
    proto: u8,
    hop_limit: u8,
}

#[derive(Debug)]
#[allow(unused)]
struct Envelope {
    ifid: IfId,
    pkt_or_error: io::Result<Ipv6Packet>,
}

#[derive(Debug)]
pub struct WriteInterest {
    handle: IOHandle,
    fd: Fd,
}

#[derive(Debug)]
pub struct RawV6SocketHandle {
    pub(super) proto: u8,
    pub(super) all_icmp: bool,
    tx: Sender<Envelope>,
    write_interests: Vec<Waker>,
}

impl RawV6Socket {
    pub fn new(proto: u8) -> io::Result<Self> {
        let handle = ioctx();
        let (fd, rx) = handle.do_failable(|ctx| ctx.ipv6_raw_socket_create(proto))?;
        Ok(Self {
            handle,
            fd,
            rx,
            cfg: Config {
                proto,
                hop_limit: 32,
            },
        })
    }

    pub async fn bind<A: ToSocketAddrs>(&self, addrs: A) -> io::Result<()> {
        let addrs = lookup_host(addrs).await?;
        let mut last_err = None;
        for addr in addrs {
            match self
                .handle
                .do_failable(|ctx| ctx.socket_bind(self.fd, addr))
            {
                Ok(_) => return Ok(()),
                Err(err) => last_err = Some(err),
            }
        }

        Err(last_err.unwrap_or_else(|| {
            Error::new(ErrorKind::InvalidInput, "could not resolve to any address")
        }))
    }

    pub async fn connect<A: ToSocketAddrs>(&self, addrs: A) -> io::Result<()> {
        let addrs = lookup_host(addrs).await?;
        let mut last_err = None;
        for addr in addrs {
            match self
                .handle
                .do_failable(|ctx| ctx.socket_set_peer(self.fd, addr))
            {
                Ok(_) => return Ok(()),
                Err(err) => last_err = Some(err),
            }
        }

        Err(last_err.unwrap_or_else(|| {
            Error::new(ErrorKind::InvalidInput, "could not resolve to any address")
        }))
    }

    /// Returns the local address that this socket is bound to.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.handle.do_io(|ctx| ctx.socket_get_addr(self.fd))
    }

    /// Returns the peer address that this socket is bound to.
    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.handle.do_io(|ctx| ctx.socket_get_peer(self.fd))
    }

    pub fn set_all_icmp(&mut self) -> io::Result<()> {
        self.handle.do_failable(|ctx| {
            let handle = ctx
                .ipv6
                .sockets
                .get_mut(&self.fd)
                .ok_or_else(|| Error::new(ErrorKind::InvalidData, "no such fd"))?;
            handle.all_icmp = true;
            Ok(())
        })
    }

    pub fn set_ttl(&mut self, ttl: u8) -> io::Result<()> {
        self.cfg.hop_limit = ttl;
        Ok(())
    }

    pub fn ttl(&self) -> io::Result<u8> {
        Ok(self.cfg.hop_limit)
    }

    pub async fn writeable(&mut self) -> io::Result<()> {
        WriteInterest {
            handle: self.handle.clone(),
            fd: self.fd,
        }
        .await
    }

    pub async fn send(&mut self, buf: &[u8]) -> io::Result<usize> {
        loop {
            self.writeable().await?;
            match self.try_send(buf) {
                Ok(n) => return Ok(n),
                Err(e) if e.kind() == ErrorKind::WouldBlock => continue,
                Err(e) => return Err(e),
            }
        }
    }

    pub fn try_send(&mut self, buf: &[u8]) -> io::Result<usize> {
        let peer = self.peer_addr()?;
        let pkt = Ipv6Packet {
            traffic_class: 0,
            flow_label: 0,
            proto: self.cfg.proto,
            hop_limit: self.cfg.hop_limit,
            extension_headers: Vec::new(),
            src: as_ipv6(
                self.local_addr()
                    .map(|v| v.ip())
                    .unwrap_or(Ipv6Addr::UNSPECIFIED.into()),
            ),
            dst: as_ipv6(peer.ip()),
            content: Bytes::copy_from_slice(buf),
        };

        self.handle.do_failable(|ctx| ctx.ipv6_send(pkt, None))?;
        Ok(buf.len())
    }

    pub async fn recv(&mut self) -> io::Result<Ipv6Packet> {
        self.rx
            .recv()
            .await
            .ok_or_else(|| Error::new(ErrorKind::UnexpectedEof, "unexpected eof"))
            .and_then(|v| v.pkt_or_error)
    }

    pub fn try_recv(&mut self) -> io::Result<Ipv6Packet> {
        self.rx
            .try_recv()
            .map_err(|err| match err {
                TryRecvError::Empty => Error::new(ErrorKind::WouldBlock, "would block"),
                TryRecvError::Disconnected => {
                    Error::new(ErrorKind::UnexpectedEof, "unexpexted eof")
                }
            })
            .and_then(|v| v.pkt_or_error)
    }
}

impl Drop for RawV6Socket {
    fn drop(&mut self) {
        self.handle.try_do_io(|ctx| {
            let _ = ctx.socket_close(self.fd);
            let _ = ctx.ipv6.sockets.remove(&self.fd);
        });
    }
}

impl Future for WriteInterest {
    type Output = io::Result<()>;
    fn poll(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        self.handle.do_io(|ctx| {
            let ifid = ctx.iface_for_write_intention(self.fd)?;
            let iface = ctx.ifaces.get_mut(&ifid).unwrap();
            let socket = ctx.ipv6.sockets.get_mut(&self.fd).unwrap();

            if iface.is_busy() {
                iface.add_write_interest(self.fd);
                socket.write_interests.push(cx.waker().clone());
                Poll::Pending
            } else {
                Poll::Ready(Ok(()))
            }
        })
    }
}

impl RawV6SocketHandle {
    pub(super) fn recv(&mut self, ifid: IfId, pkt: Ipv6Packet) {
        if let Err(err) = self.tx.try_send(Envelope {
            ifid,
            pkt_or_error: Ok(pkt),
        }) {
            todo!("{err}")
        }
    }

    pub(super) fn recv_error(&mut self, ifid: IfId, err: Error) {
        if let Err(err) = self.tx.try_send(Envelope {
            ifid,
            pkt_or_error: Err(err),
        }) {
            todo!("{err}")
        }
    }
}

impl IOContext {
    pub(crate) fn ipv6_raw_socket_link_update(&mut self, fd: Fd) {
        let Some(sockets) = self.ipv6.sockets.get_mut(&fd) else {
            return;
        };

        sockets.write_interests.drain(..).for_each(Waker::wake);
    }

    pub(super) fn ipv6_raw_socket_on_icmp(
        &mut self,
        ifid: IfId,
        fd: Fd,
        msg: &IcmpV6Packet,
        contained: &Ipv6Packet,
    ) {
        let Some(handle) = self.ipv6.sockets.get_mut(&fd) else {
            return;
        };
        let Ok(socket) = self.sockets.get(fd) else {
            return;
        };

        let is_valid = socket.addr.ip().is_unspecified() || socket.addr.ip() == contained.src;
        if !is_valid {
            return;
        }

        let should_report =
            handle.all_icmp || matches!(msg, IcmpV6Packet::DestinationUnreachable(_));

        if should_report {
            let error = Error::new(ErrorKind::ConnectionRefused, msg.as_error_string());
            handle.recv_error(ifid, error);
        }
    }

    fn ipv6_raw_socket_create(&mut self, proto: u8) -> io::Result<(Fd, Receiver<Envelope>)> {
        let fd = self.socket_create(SocketDomain::AF_INET6, SocketType::SOCK_RAW, proto as i32)?;

        let (tx, rx) = channel(16);

        self.ipv6.sockets.insert(
            fd,
            RawV6SocketHandle {
                all_icmp: false,
                proto,
                tx,
                write_interests: Vec::new(),
            },
        );

        Ok((fd, rx))
    }
}

fn as_ipv6(ip: IpAddr) -> Ipv6Addr {
    match ip {
        IpAddr::V6(v6) => v6,
        _ => unreachable!("should be impossible"),
    }
}
