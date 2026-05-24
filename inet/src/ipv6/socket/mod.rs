use std::{
    io::{self, Error, ErrorKind},
    net::{IpAddr, Ipv6Addr, SocketAddr},
    task::{Poll, Waker},
};

use bytes_io::Bytes;
use fxhash::FxHashSet;
use tokio::sync::mpsc::{Receiver, Sender, channel, error::TryRecvError};
use types::{icmpv6::IcmpV6Packet, ip::Ipv6Packet};

use crate::{
    IOHandle,
    ctx::IOContext,
    interface::IfId,
    ioctx,
    ipv6::Ipv6SendFlags,
    socket::{AsRawFd, Fd, SocketDomain, SocketType},
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
    local_addr: Ipv6Addr,
    tx: Sender<Envelope>,
    write_interests: Vec<Waker>,
    multicast_listeners_v6: FxHashSet<Ipv6Addr>,
}

impl RawV6Socket {
    pub fn new(proto: u8) -> io::Result<Self> {
        let handle = ioctx();
        let (fd, rx) =
            handle.do_mutating_on_active_module(|ctx| ctx.ipv6_raw_socket_create(proto))?;
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

    pub fn bind(&self, addr: Ipv6Addr) -> io::Result<()> {
        self.handle.do_mutating_on_active_module(|ctx| {
            ctx.socket_bind(self.fd, SocketAddr::new(addr.into(), 0))?;
            ctx.ipv6
                .sockets
                .get_mut(&self.fd)
                .expect("illegal state")
                .local_addr = addr;
            Ok(())
        })
    }

    pub fn connect(&self, addr: Ipv6Addr) -> io::Result<()> {
        self.handle.do_mutating_on_active_module(|ctx| {
            ctx.socket_set_peer(self.fd, SocketAddr::new(addr.into(), 0))
        })
    }

    /// Returns the local address that this socket is bound to.
    pub fn local_addr(&self) -> io::Result<Ipv6Addr> {
        self.handle
            .do_mutating(|ctx| ctx.socket_get_addr(self.fd))
            .map(|sock| as_ipv6(sock.ip()))
    }

    /// Returns the peer address that this socket is bound to.
    pub fn peer_addr(&self) -> io::Result<Ipv6Addr> {
        self.handle
            .do_mutating(|ctx| ctx.socket_get_peer(self.fd))
            .map(|sock| as_ipv6(sock.ip()))
    }

    pub fn set_all_icmp(&mut self) -> io::Result<()> {
        self.handle.do_mutating_on_active_module(|ctx| {
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
        let peer = self.peer_addr()?;
        self.send_to(buf, peer).await
    }

    pub async fn send_to(&mut self, buf: &[u8], dst: Ipv6Addr) -> io::Result<usize> {
        loop {
            self.writeable().await?;
            match self.try_send_to(buf, dst) {
                Ok(n) => return Ok(n),
                Err(e) if e.kind() == ErrorKind::WouldBlock => continue,
                Err(e) => return Err(e),
            }
        }
    }

    pub fn try_send(&mut self, buf: &[u8]) -> io::Result<usize> {
        let peer = self.peer_addr()?;
        self.try_send_to(buf, peer)
    }

    pub fn try_send_to(&mut self, buf: &[u8], dst: Ipv6Addr) -> io::Result<usize> {
        let pkt = Ipv6Packet {
            traffic_class: 0,
            flow_label: 0,
            proto: self.cfg.proto,
            hop_limit: self.cfg.hop_limit,
            extension_headers: Vec::new(),
            src: self.local_addr().unwrap_or(Ipv6Addr::UNSPECIFIED),
            dst,
            content: Bytes::copy_from_slice(buf),
        };
        self.handle.do_mutating_on_active_module(|ctx| {
            ctx.ipv6_send_with_flags(pkt, None, Ipv6SendFlags::ALLOW_FRAGMENTATION)
        })?;
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

    pub fn join_multicast(&mut self, addr: Ipv6Addr) -> io::Result<()> {
        self.handle.do_mutating_on_active_module(|ctx| {
            let socket = ctx.ipv6.sockets.get_mut(&self.fd).unwrap();
            if !socket.multicast_listeners_v6.insert(addr) {
                return Err(Error::new(ErrorKind::AddrInUse, "address already in use"));
            }

            // socket.publish();
            ctx.ipv6_join_multicast_group(addr, None)
        })
    }
}

impl AsRawFd for RawV6Socket {
    fn as_raw_fd(&self) -> Fd {
        self.fd
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
        self.handle.do_mutating(|ctx| {
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
        let is_valid = self.local_addr.is_unspecified()
            || self.local_addr == pkt.dst
            || self.multicast_listeners_v6.contains(&pkt.dst);

        if !is_valid {
            return;
        }

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
                multicast_listeners_v6: FxHashSet::default(),
                local_addr: Ipv6Addr::UNSPECIFIED,
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
