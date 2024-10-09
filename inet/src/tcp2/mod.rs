use crate::{
    interface::{IfId, KIND_IO_TIMEOUT},
    socket::{Fd, SocketDomain, SocketIfaceBinding, SocketType},
    IOContext,
};

use bytepack::{FromBytestream, ToBytestream};
use des::prelude::{schedule_at, Message};
use fxhash::FxHashMap;
use listener::Listener;
use sender::TcpSenderBuffer;
use std::{
    io::{Error, ErrorKind},
    mem,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc,
    },
    task::{Context, Poll},
};
use tokio::{io::ReadBuf, sync::mpsc};
use types::{
    ip::IpPacketRef,
    tcp::{TcpFlags, TcpPacket, PROTO_TCP},
};

//
//
//
pub const PROTO_TCP2: u8 = PROTO_TCP + 1;
//
//
//

mod connection;
mod interest;
mod listener;
mod sender;
mod stream;

pub use connection::{Config, Connection, State};
pub use listener::TcpListener;
pub use stream::TcpStream;

#[cfg(test)]
mod tests;

pub struct Tcp {
    pub config: Config,
    pub sender: TcpSenderBuffer,
    pub listeners: FxHashMap<Fd, Listener>,
    pub streams: FxHashMap<Fd, Connection>,
    pub active: Vec<Fd>,
}

#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq)]
pub struct Quad {
    pub src: SocketAddr,
    pub dst: SocketAddr,
}

impl Tcp {
    pub fn new() -> Self {
        Tcp {
            config: Config::default(),
            sender: TcpSenderBuffer::default(),
            listeners: FxHashMap::default(),
            streams: FxHashMap::default(),
            active: Vec::default(),
        }
    }

    pub fn set_error(&mut self, fd: Fd, error: Error) {
        if let Some(stream) = self.streams.get_mut(&fd) {
            tracing::error!(%fd, ?error, "connection failed with error");
            stream.error = Some(error);
        }
    }

    pub fn set_active(&mut self, fd: Fd) {
        if !self.active.contains(&fd) {
            self.active.push(fd);
        }
    }
}

impl IOContext {
    pub fn tcp2_socket_link_update(&mut self, fd: Fd) {
        let Some(socket) = self.sockets.get(&fd) else {
            return;
        };
        let Some(interface) = self.ifaces.get_mut(&socket.interface.unwrap_ifid()) else {
            return;
        };

        let mut sender = self.tcp2.sender.sender(fd);

        if !interface.is_busy() {
            let Some(pkt) = sender.next(Quad {
                src: socket.addr,
                dst: socket.peer,
            }) else {
                return;
            };

            if !sender.is_empty() {
                interface.add_write_interest(fd);
            }

            if let Err(error) = self.send_ip_packet(socket.interface.clone(), pkt, true) {
                self.tcp2.set_error(fd, error);
            }
        } else {
            if !sender.is_empty() {
                interface.add_write_interest(fd);
            }
        }
    }

    pub fn tcp2_timeout(&mut self, fd: Fd) {
        self.tcp2.set_active(fd);
    }

    #[tracing::instrument(skip(self))]
    pub fn tcp2_tick(&mut self) {
        let mut fds = Vec::new();
        mem::swap(&mut fds, &mut self.tcp2.active);

        for fd in &fds {
            let Some(con) = self.tcp2.streams.get_mut(fd) else {
                continue;
            };

            con.on_tick(&mut self.tcp2.sender.sender(*fd))
                .expect("on tick failure");

            if let Some(deadline) = con.next_timeout() {
                schedule_at(
                    Message::new().kind(KIND_IO_TIMEOUT).content(*fd).build(),
                    deadline,
                );
            }
        }

        for fd in &fds {
            self.tcp2_socket_link_update(*fd);
        }
    }

    pub fn tcp2_connection<R>(
        &mut self,
        fd: Fd,
        f: impl FnOnce(&mut Connection) -> R,
    ) -> Result<R, Error> {
        let con = self
            .tcp2
            .streams
            .get_mut(&fd)
            .ok_or(Error::new(ErrorKind::BrokenPipe, "no such fd"))?;

        let result = f(con);
        con.on_tick(&mut self.tcp2.sender.sender(fd))?;
        self.tcp2_socket_link_update(fd);
        Ok(result)
    }

    //
    // # Packet Handeling
    //

    pub fn tcp2_on_packet(&mut self, ip_packet: IpPacketRef, ifid: IfId) -> bool {
        assert_eq!(ip_packet.tos(), PROTO_TCP2);

        let Ok(pkt) = TcpPacket::from_slice(ip_packet.content()) else {
            tracing::error!(
                "received ip-packet with proto=0x06 (tcp) but content was no tcp-packet"
            );
            return false;
        };

        let src = SocketAddr::new(ip_packet.src(), pkt.src_port);
        let dest = SocketAddr::new(ip_packet.dest(), pkt.dst_port);

        // (0) All sockets that are bound to the correct destination (local) address
        let mut valid_sockets = self
            .sockets
            .iter_mut()
            .filter(|(_, sock)| {
                sock.typ == SocketType::SOCK_STREAM && is_valid_dest_for(&sock.addr, &dest)
            })
            .collect::<Vec<_>>();

        // (1) Check whether a packet belongs to an existing packet.
        if let Some((fd, sock)) = valid_sockets.iter_mut().find(|v| v.1.peer == src) {
            // (1) Active stream socket
            if !sock.interface.contains(&ifid) {
                tracing::error!("interface missmatch");
                return false;
            }

            sock.recv_q += pkt.content.len();

            let fd = **fd;
            return self.tcp2_connection_on_packet(fd, pkt);
        }

        if pkt.flags.contains(TcpFlags::SYN) || !pkt.flags.contains(TcpFlags::ACK) {
            // SYN

            // (2) Check for active listeners
            if let Some((fd, sock)) = valid_sockets
                .iter()
                .find(|(_, s)| s.peer.ip().is_unspecified() && s.peer.port() == 0)
            {
                if !sock.interface.contains(&ifid) {
                    tracing::error!("interface missmatch");
                    return false;
                }

                let fd = **fd;
                return self.tcp2_listener_on_packet(ip_packet, fd, pkt);
            }

            if self.tcp2.config.rst_for_syn {
                tracing::trace!("invalid incoming connection, sending RST");

                let rst = TcpPacket::rst_for_syn(&pkt);
                let rst = ip_packet.response(rst.to_vec().unwrap());
                self.send_ip_packet(SocketIfaceBinding::Bound(ifid), rst, true)
                    .expect("failed to send");
                true
            } else {
                tracing::trace!("invalid incoming connection, ignoring");
                false
            }
        } else {
            false
        }
    }

    fn tcp2_connection_on_packet(&mut self, fd: Fd, pkt: TcpPacket) -> bool {
        let Some(connection) = self.tcp2.streams.get_mut(&fd) else {
            tracing::error!("found tcp socket, but missing tcp manager");
            return false;
        };

        connection
            .on_packet(&mut self.tcp2.sender.sender(fd), pkt)
            .expect("failed to recv");
        self.tcp2_socket_link_update(fd);
        true
    }

    ///
    /// TCP ready()
    ///

    ///
    /// TCP read()
    ///

    pub fn tcp2_read(
        &mut self,
        fd: Fd,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<usize, Error>> {
        let Some(con) = self.tcp2.streams.get_mut(&fd) else {
            todo!()
        };

        match con.read(buf.initialize_unfilled()) {
            Ok(n) => {
                self.tcp2.set_active(fd);
                // Alternative:
                // on_tick() + tcp2_ll_update
                Poll::Ready(Ok(n))
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock => {
                con.rx_wakers.push(cx.waker().clone());
                Poll::Pending
            }
            Err(e) => Poll::Ready(Err(e)),
        }
    }

    ///
    /// TCP write()
    ///

    pub fn tcp2_write(
        &mut self,
        fd: Fd,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, Error>> {
        let Some(con) = self.tcp2.streams.get_mut(&fd) else {
            todo!()
        };

        match con.write(buf) {
            Ok(n) => {
                self.tcp2.set_active(fd);
                // Alternative:
                // on_tick() + tcp2_ll_update
                Poll::Ready(Ok(n))
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock => {
                con.tx_wakers.push(cx.waker().clone());
                Poll::Pending
            }
            Err(e) => Poll::Ready(Err(e)),
        }
    }

    pub fn tcp2_flush(&mut self, fd: Fd, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        let Some(con) = self.tcp2.streams.get_mut(&fd) else {
            todo!()
        };

        if con.unacked.is_empty() {
            Poll::Ready(Ok(()))
        } else {
            con.tx_wakers.push(cx.waker().clone());
            Poll::Pending
        }
    }

    ///
    /// TCP bind()
    ///

    fn tcp2_bind(
        &mut self,
        mut addr: SocketAddr,
        cfg: Option<Config>,
        fd: Option<Fd>,
    ) -> Result<TcpListener, Error> {
        let fd = if let Some(fd) = fd {
            fd
        } else {
            let domain = if addr.is_ipv4() {
                SocketDomain::AF_INET
            } else {
                SocketDomain::AF_INET6
            };
            let fd = self.create_socket(domain, SocketType::SOCK_STREAM, 0)?;

            addr = self.bind_socket(fd, addr).map_err(|e| {
                self.close_socket(self.fd).expect("cannot handle error");
                e
            })?;
            fd
        };

        let (tx, rx) = mpsc::channel(32);

        let backlog = Arc::new(AtomicU32::new(0));
        let handle = Listener {
            local_addr: addr,
            backlog: backlog.clone(),
            tx,
            config: cfg.unwrap_or(self.tcp2.config.for_listener(addr)),
        };

        self.tcp2.listeners.insert(fd, handle);

        Ok(TcpListener::from_raw(fd, rx, backlog))
    }

    fn tcp2_unbind(&mut self, fd: Fd) {
        self.tcp.listeners.remove(&fd);
        self.close_socket(fd).expect("failed to unbind");
    }

    ///
    /// TCP accept()
    ///

    fn tcp2_listener_on_packet(&mut self, ip_packet: IpPacketRef, fd: Fd, pkt: TcpPacket) -> bool {
        let src = SocketAddr::new(ip_packet.src(), pkt.src_port);
        let dst = SocketAddr::new(ip_packet.dest(), pkt.dst_port);

        let Some(listener) = self.tcp2.listeners.get_mut(&fd) else {
            tracing::error!("found tcp socket, but missing tcp listener");
            return false;
        };

        let cfg = listener.config.clone();
        if listener.backlog.load(Ordering::SeqCst) >= 32 {
            return true;
        }
        listener.backlog.fetch_add(1, Ordering::SeqCst);

        let stream = match self.tcp2_listener_on_packet_failable(fd, src, pkt, cfg) {
            Ok(v) => v,
            Err(e) => {
                let handle = self.tcp2.listeners.get_mut(&fd).unwrap();
                handle.tx.try_send(Err(e)).expect("unreachable");
                return true;
            }
        };

        let listener = self.tcp2.listeners.get_mut(&fd).expect("unreachable");
        listener.tx.try_send(Ok(stream)).expect("unreachable");

        tracing::trace!("incoming connection to {dst} from {src}");

        true
    }

    fn tcp2_listener_on_packet_failable(
        &mut self,
        fd: u32,
        src: SocketAddr,
        pkt: TcpPacket,
        cfg: Config,
    ) -> Result<Fd, Error> {
        let stream_socket = self.dup_socket(fd)?;
        self.bind_peer(stream_socket, src)?;
        let quad = Quad {
            src: self.get_socket_addr(stream_socket)?,
            dst: src,
        };
        let con = Connection::accept(&mut self.tcp2.sender.sender(stream_socket), quad, pkt, cfg)?;
        if let Some(con) = con {
            self.tcp2.streams.insert(stream_socket, con);
        }
        self.tcp2_socket_link_update(stream_socket);
        Ok(stream_socket)
    }

    ///
    /// # TCP connect()
    ///

    fn tcp2_connect(
        &mut self,
        peer: SocketAddr,
        cfg: Option<Config>,
        fd: Option<Fd>,
    ) -> Result<Fd, Error> {
        let (fd, cfg) = if let Some(fd) = fd {
            // check whether socket was bound.
            let Some(socket) = self.sockets.get(&fd) else {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    "invalid fd - socket dropped",
                ));
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

            (fd, cfg.unwrap())
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

            let config = cfg.unwrap_or(self.tcp2.config.for_listener(addr));
            (fd, config)
        };

        self.bind_peer(fd, peer)?;

        let local_addr = self.get_socket_addr(fd)?;
        let quad = Quad {
            src: local_addr,
            dst: peer,
        };

        // Sends a SYN
        let conn = Connection::connect(&mut self.tcp2.sender.sender(fd), quad, cfg)?;
        self.tcp2.streams.insert(fd, conn);
        self.tcp2.set_active(fd);

        // -> FWD SYN (TODO: rm)
        self.tcp2_socket_link_update(fd);

        Ok(fd)
    }

    //
    // # TCP drop
    //

    fn tcp2_drop(&mut self, fd: Fd) -> Result<(), Error> {
        let con = self
            .tcp2
            .streams
            .get_mut(&fd)
            .ok_or(Error::new(ErrorKind::BrokenPipe, "no such fd"))?;

        con.close()?;
        Ok(())
    }
}

impl Quad {
    pub fn is_ipv4(&self) -> bool {
        self.src.is_ipv4() && self.dst.is_ipv4()
    }

    fn default_mss(&self) -> u16 {
        if self.is_ipv4() {
            536
        } else {
            1220
        }
    }
}

fn is_valid_dest_for(socket_addr: &SocketAddr, packet_addr: &SocketAddr) -> bool {
    if socket_addr.ip().is_unspecified() {
        return socket_addr.port() == packet_addr.port();
    }

    match packet_addr {
        SocketAddr::V4(_) => socket_addr == packet_addr,
        SocketAddr::V6(_) => socket_addr == packet_addr,
    }
}

pub fn set_config(config: Config) {
    IOContext::with_current(|ctx| ctx.tcp2.config = config)
}
