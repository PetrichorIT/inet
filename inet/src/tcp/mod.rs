use crate::{
    IOContext, IOHandle,
    interface::{IfId, KIND_IO_TIMEOUT},
    io::Interest,
    socket::{Fd, SocketDomain, SocketIfaceBinding, SocketType},
};

use bytes_io::{FromBytes, ToBytes};
use des::{
    prelude::{Message, schedule_at},
    time::SimTime,
};
use fxhash::FxHashMap;
use std::{
    io::{Error, ErrorKind},
    mem,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    sync::atomic::Ordering,
    task::{Context, Poll},
};
use tokio::io::ReadBuf;
use types::{
    icmpv4::IcmpV4Packet,
    icmpv6::IcmpV6Packet,
    ip::{IpPacketRef, Ipv4Packet, Ipv6Packet},
    tcp::{PROTO_TCP, TcpFlags, TcpPacket},
};

mod connection;
mod interest;
mod listener;
mod socket;
mod stream;

use listener::Listener;

pub use connection::{Config, Connection, State};
pub use listener::TcpListener;
pub use socket::TcpSocket;
pub use stream::{OwnedReadHalf, OwnedWriteHalf, ReadHalf, TcpStream, WriteHalf};

#[cfg(test)]
mod tests;

#[derive(Default)]
pub struct Tcp {
    pub config: Config,
    timers: Timers,
    listeners: FxHashMap<Fd, Listener>,
    pub streams: FxHashMap<Fd, Connection>,
    pub active: Vec<Fd>,
}

#[derive(Debug, Default)]
struct Timers {
    pub needed_wakeups: FxHashMap<Fd, SimTime>,
    pub scheduled: Vec<SimTime>,
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
            timers: Timers::default(),
            listeners: FxHashMap::default(),
            streams: FxHashMap::default(),
            active: Vec::default(),
        }
    }

    fn set_error(&mut self, fd: Fd, error: Error) {
        if let Some(stream) = self.streams.get_mut(&fd) {
            tracing::error!(%fd, ?error, "connection failed with error");
            stream.interface.set_error(error);
            stream.interface.wake(Interest::BOTH);
        }
    }

    fn set_active(&mut self, fd: Fd) {
        if !self.active.contains(&fd) {
            self.active.push(fd);
        }
    }
}

impl IOContext {
    pub fn tcp_on_icmpv4(&mut self, fd: Fd, icmp: &IcmpV4Packet, contained: &Ipv4Packet) {
        let _ = self.tcp_connection(fd, |con| con.on_icmp_v4(icmp, contained));
    }
    pub fn tcp_on_icmpv6(&mut self, fd: Fd, icmp: &IcmpV6Packet, contained: &Ipv6Packet) {
        let _ = self.tcp_connection(fd, |con| con.on_icmp_v6(icmp, contained));
    }

    pub fn tcp_on_mtu_change(&mut self, fd: Fd, mtu: usize) {
        let _ = self.tcp_connection(fd, |con| con.change_mtu(mtu));
    }

    pub fn tcp_socket_link_update(&mut self, fd: Fd) {
        let Some(socket) = self.sockets.get(&fd) else {
            return;
        };
        let Some(interface) = self.ifaces.get_mut_spec(&socket.interface.into_ifspec()) else {
            return;
        };
        let Some(con) = self.tcp.streams.get_mut(&fd) else {
            return;
        };

        if !interface.is_busy() {
            let Some((pkt, segn)) = con.outgoing_next() else {
                return;
            };
            con.timers.update_send_time(segn, SimTime::now());
            let is_empty = con.outgoing.is_empty();

            if let Err(error) = self.send_ip_packet(socket.interface.clone(), pkt) {
                self.tcp.set_error(fd, error);
            }

            // TODO: that is just horrible
            let Some(socket) = self.sockets.get(&fd) else {
                return;
            };
            let Some(interface) = self.ifaces.get_mut_spec(&socket.interface.into_ifspec()) else {
                return;
            };
            if !is_empty {
                interface.add_write_interest(fd);
            }
        } else if !con.outgoing.is_empty() {
            interface.add_write_interest(fd);
        }
    }

    pub fn tcp_timeout(&mut self) {
        // TCP2 grouped wakeup
        for fd in self.tcp.timers.on_wakeup() {
            // We cannot defer any work, since timeouts could cause async progerss
            // this can lead to two calls to on_tick per event
            let Some(con) = self.tcp.streams.get_mut(&fd) else {
                continue;
            };

            con.on_tick().expect("on tick failure");

            self.tcp.set_active(fd);
        }
    }

    #[tracing::instrument(skip(self))]
    pub fn tcp_tick(&mut self) {
        // TODO:
        // need to check, whether the tick caused some
        // wakers to be woken. If yes, then
        // schedule a 0s reactivation to use these wakers

        let mut fds = Vec::new();
        mem::swap(&mut fds, &mut self.tcp.active);

        for fd in &fds {
            let Some(con) = self.tcp.streams.get_mut(fd) else {
                continue;
            };

            con.on_tick().expect("on tick failure");
            self.tcp.timers.update(*fd, con);
        }

        for fd in &fds {
            self.tcp_socket_link_update(*fd);
        }

        // Remove closed sockets
        for fd in &fds {
            if self
                .tcp
                .streams
                .get(fd)
                .is_some_and(|con| con.state == State::Closed)
            {
                self.tcp_drop(*fd).expect("failed");
            }
        }

        // if self.tcp2.sender.has_unresolved_wakeups {
        //     // Apparently, this is never true
        //     // this cannot be right i think, but maybe it is
        //     // TODO: check for timeouts
        //     // TODO: if there are wakeups in the event_end_tick, reschedule a 0s event, to resolve the wakeups
        //     unreachable!()
        // }

        self.tcp.timers.schedule()
    }

    pub fn tcp_connection<R>(
        &mut self,
        fd: Fd,
        f: impl FnOnce(&mut Connection) -> R,
    ) -> Result<R, Error> {
        let con = self
            .tcp
            .streams
            .get_mut(&fd)
            .ok_or(Error::new(ErrorKind::BrokenPipe, "no such fd"))?;

        // TODO: is this a good idea?
        // if let Some(error) = con.error.take() {
        //     return Err(error);
        // }
        let result = f(con);
        self.tcp.set_active(fd);
        Ok(result)
    }

    //
    // # Packet Handeling
    //

    pub fn tcp_on_packet(&mut self, ip_packet: IpPacketRef, ifid: IfId) -> bool {
        assert_eq!(ip_packet.tos(), PROTO_TCP);

        let Ok(pkt) = TcpPacket::peek_from(ip_packet.content()) else {
            tracing::error!(
                "received ip-packet with proto=0x06 (tcp) but content was no tcp-packet"
            );
            return false;
        };

        let src = SocketAddr::new(ip_packet.src(), pkt.src_port);
        let dest = SocketAddr::new(ip_packet.dst(), pkt.dst_port);

        // (0) All sockets that are bound to the correct destination (local) address
        let mut valid_sockets = self
            .sockets
            .iter_mut()
            .filter(|(_, sock)| {
                sock.typ == SocketType::SOCK_STREAM && is_valid_dst_for(&sock.addr, &dest)
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
            return self.tcp_connection_on_packet(fd, pkt);
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
                return self.tcp_listener_on_packet(ip_packet, fd, pkt);
            }

            if self.tcp.config.rst_for_syn {
                tracing::trace!("invalid incoming connection, sending RST");

                let rst = TcpPacket::rst_for_syn(&pkt);
                let rst = ip_packet.response(rst.write_to_bytes().unwrap());
                self.send_ip_packet(SocketIfaceBinding::Bound(ifid), rst)
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

    fn tcp_connection_on_packet(&mut self, fd: Fd, pkt: TcpPacket) -> bool {
        let Some(connection) = self.tcp.streams.get_mut(&fd) else {
            tracing::error!("found tcp socket, but missing tcp manager");
            return false;
        };

        connection.on_packet(pkt).expect("failed to recv");
        self.tcp.set_active(fd);

        true
    }

    //
    // TCP ready()
    //

    //
    // TCP read()
    //

    pub fn tcp_read(&mut self, fd: Fd, buf: &mut [u8]) -> Result<usize, Error> {
        let Some(con) = self.tcp.streams.get_mut(&fd) else {
            todo!()
        };

        con.read(buf).inspect(|_| {
            self.tcp.set_active(fd);
        })
    }

    pub fn tcp_peek(&mut self, fd: Fd, buf: &mut [u8]) -> Result<usize, Error> {
        let Some(con) = self.tcp.streams.get_mut(&fd) else {
            todo!()
        };

        con.peek(buf).inspect(|_| {
            self.tcp.set_active(fd);
        })
    }

    pub fn tcp_poll_read(
        &mut self,
        fd: Fd,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<usize, Error>> {
        let Some(con) = self.tcp.streams.get_mut(&fd) else {
            todo!()
        };

        match con.read(buf.initialize_unfilled()) {
            Ok(n) => {
                self.tcp.set_active(fd);
                // Alternative:
                // on_tick() + tcp_ll_update
                Poll::Ready(Ok(n))
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock => {
                con.interface.register(Interest::READABLE, cx);
                Poll::Pending
            }
            Err(e) => Poll::Ready(Err(e)),
        }
    }

    pub fn tcp_poll_peek(
        &mut self,
        fd: Fd,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<usize, Error>> {
        let Some(con) = self.tcp.streams.get_mut(&fd) else {
            todo!()
        };

        match con.peek(buf.initialize_unfilled()) {
            Ok(n) => {
                // No set_active since peek does not consume data
                Poll::Ready(Ok(n))
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock => {
                con.interface.register(Interest::READABLE, cx);
                Poll::Pending
            }
            Err(e) => Poll::Ready(Err(e)),
        }
    }

    //
    // TCP write()
    //

    pub fn tcp_write(&mut self, fd: Fd, buf: &[u8]) -> Result<usize, Error> {
        let Some(con) = self.tcp.streams.get_mut(&fd) else {
            todo!()
        };

        con.write(buf).inspect(|_| {
            self.tcp.set_active(fd);
        })
    }

    pub fn tcp_poll_write(
        &mut self,
        fd: Fd,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, Error>> {
        let Some(con) = self.tcp.streams.get_mut(&fd) else {
            todo!()
        };

        match con.write(buf) {
            Ok(n) => {
                self.tcp.set_active(fd);
                // Alternative:
                // on_tick() + tcp_ll_update
                Poll::Ready(Ok(n))
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock => {
                con.interface.register(Interest::WRITABLE, cx);
                Poll::Pending
            }
            Err(e) => Poll::Ready(Err(e)),
        }
    }

    pub fn tcp_flush(&mut self, fd: Fd, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        let Some(con) = self.tcp.streams.get_mut(&fd) else {
            todo!()
        };

        if con.is_flushed() {
            Poll::Ready(Ok(()))
        } else {
            con.interface.register(Interest::WRITABLE, cx);
            Poll::Pending
        }
    }

    //
    // TCP bind()
    //

    fn tcp_bind(
        &mut self,
        mut addr: SocketAddr,
        cfg: Option<Config>,
        fd: Option<Fd>,
        backlog: Option<usize>,
    ) -> Result<TcpListener, Error> {
        let fd = if let Some(fd) = fd {
            fd
        } else {
            let domain = if addr.is_ipv4() {
                SocketDomain::AF_INET
            } else {
                SocketDomain::AF_INET6
            };
            let fd = self.socket(domain, SocketType::SOCK_STREAM, 0)?;

            addr = self.socket_bind(fd, addr).inspect_err(|_| {
                self.socket_close(fd).expect("cannot handle error");
            })?;
            fd
        };

        let (handle, rx, backlog) = Listener::create(
            addr,
            cfg.unwrap_or(self.tcp.config.for_listener(addr)),
            backlog.unwrap_or(32),
        );
        self.tcp.listeners.insert(fd, handle);

        Ok(TcpListener::from_raw(fd, rx, self.handle(), backlog))
    }

    fn tcp_unbind(&mut self, fd: Fd) {
        self.tcp
            .listeners
            .remove(&fd)
            .expect("failed to unbind tcp listener");
    }

    //
    // TCP accept()
    //

    fn tcp_listener_on_packet(&mut self, ip_packet: IpPacketRef, fd: Fd, pkt: TcpPacket) -> bool {
        let src = SocketAddr::new(ip_packet.src(), pkt.src_port);
        let dst = SocketAddr::new(ip_packet.dst(), pkt.dst_port);

        let Some(listener) = self.tcp.listeners.get_mut(&fd) else {
            tracing::error!("found tcp socket, but missing tcp listener");
            return false;
        };

        let cfg = listener.config.clone();
        if listener.backlog.load(Ordering::SeqCst) >= listener.backlog_limit {
            return true;
        }
        listener.backlog.fetch_add(1, Ordering::SeqCst);

        let stream = match self.tcp_listener_on_packet_failable(fd, src, pkt, cfg) {
            Ok(v) => v,
            Err(e) => {
                let handle = self.tcp.listeners.get_mut(&fd).unwrap();
                handle.tx.try_send(Err(e)).expect("unreachable");
                return true;
            }
        };

        let listener = self.tcp.listeners.get_mut(&fd).expect("unreachable");
        listener.tx.try_send(Ok(stream)).expect("unreachable");

        tracing::trace!("incoming connection to {dst} from {src}");

        true
    }

    fn tcp_listener_on_packet_failable(
        &mut self,
        fd: u32,
        src: SocketAddr,
        pkt: TcpPacket,
        mut cfg: Config,
    ) -> Result<Fd, Error> {
        let stream_socket = self.socket_duplicate(fd)?;
        self.socket_set_peer(stream_socket, src)?;

        let quad = Quad {
            src: self.socket_get_addr(stream_socket)?,
            dst: src,
        };

        // Set MSS based on path MTU guess
        let ip_payload_mtu = self.get_path_mtu(quad.src.ip(), quad.dst.ip());
        let mss = (ip_payload_mtu - TcpPacket::MIN_HEADER_SIZE) as u16;
        cfg.mss = Some(cfg.mss.map_or(mss, |cfg_mss| cfg_mss.min(mss)));

        let con = Connection::accept(quad, pkt, cfg)?;
        if let Some(con) = con {
            self.tcp.streams.insert(stream_socket, con);
        }
        // TODO: introduce indirection
        self.tcp_socket_link_update(stream_socket);
        Ok(stream_socket)
    }

    //
    // # TCP connect()
    //

    fn tcp_connect(
        &mut self,
        peer: SocketAddr,
        cfg: Option<Config>,
        fd: Option<Fd>,
    ) -> Result<Fd, Error> {
        let (fd, mut cfg) = if let Some(fd) = fd {
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
                self.socket_bind(fd, unspecified)?;
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

            let fd = self.socket(domain, SocketType::SOCK_STREAM, 0)?;
            let addr = self.socket_bind(fd, unspecified)?;

            let config = cfg.unwrap_or(self.tcp.config.for_listener(addr));
            (fd, config)
        };

        self.socket_set_peer(fd, peer)?;

        let local_addr = self.socket_get_addr(fd)?;
        let quad = Quad {
            src: local_addr,
            dst: peer,
        };

        // Set MSS based on path MTU guess
        let ip_payload_mtu = self.get_path_mtu(local_addr.ip(), peer.ip());
        let mss = (ip_payload_mtu - TcpPacket::MIN_HEADER_SIZE) as u16;
        cfg.mss = Some(cfg.mss.map_or(mss, |cfg_mss| cfg_mss.min(mss)));

        // Sends a SYN
        let conn = Connection::connect(quad, cfg)?;
        self.tcp.streams.insert(fd, conn);

        // Nessecary, since failure to send packets may wake up wakers
        self.tcp_socket_link_update(fd);

        Ok(fd)
    }

    //
    // # TCP drop
    //

    fn tcp_drop(&mut self, fd: Fd) -> Result<(), Error> {
        self.tcp.timers.remove(fd);
        self.tcp
            .streams
            .remove(&fd)
            .ok_or(Error::new(ErrorKind::BrokenPipe, "no such fd"))?;

        self.socket_close(fd)?;

        Ok(())
    }

    #[tracing::instrument(skip(self))]
    fn tcp_close(&mut self, fd: Fd) -> Result<(), Error> {
        self.tcp_connection(fd, |con| con.close()).flatten()
    }
}

impl Timers {
    fn on_wakeup(&mut self) -> Vec<Fd> {
        let now = SimTime::now();

        while self.scheduled.first().is_some_and(|v| *v <= now) {
            self.scheduled.remove(0);
        }

        let mut vec = Vec::new();
        for (k, v) in &self.needed_wakeups {
            if *v <= now {
                vec.push(*k);
            }
        }

        vec
    }

    fn remove(&mut self, fd: Fd) {
        self.needed_wakeups.remove(&fd);
    }

    fn schedule(&mut self) {
        let Some(min) = self.needed_wakeups.values().min().copied() else {
            return;
        };

        if min <= SimTime::now() {
            return;
        }
        let next_scheduled = self.scheduled.first().unwrap_or(&SimTime::MAX);

        if min < *next_scheduled {
            tracing::debug!("<TCP2> scheduling wakeup: {min}");
            schedule_at(
                Message::default()
                    .with_kind(KIND_IO_TIMEOUT)
                    .with_content(u32::MAX),
                min,
            );
            self.scheduled.insert(0, min);
        }
    }

    fn update(&mut self, fd: Fd, con: &Connection) {
        if let Some(next_wakeup) = con.next_timeout() {
            self.needed_wakeups.insert(fd, next_wakeup);
        } else {
            self.needed_wakeups.remove(&fd);
        }
    }
}

impl Quad {
    pub const fn reversed(&self) -> Self {
        Self {
            src: self.dst,
            dst: self.src,
        }
    }

    pub const fn is_ipv4(&self) -> bool {
        self.src.is_ipv4() && self.dst.is_ipv4()
    }

    const fn default_mss(&self) -> u16 {
        if self.is_ipv4() { 536 } else { 1220 }
    }
}

fn is_valid_dst_for(socket_addr: &SocketAddr, packet_addr: &SocketAddr) -> bool {
    if socket_addr.ip().is_unspecified() {
        return socket_addr.port() == packet_addr.port();
    }

    match packet_addr {
        SocketAddr::V4(_) => socket_addr == packet_addr,
        SocketAddr::V6(_) => socket_addr == packet_addr,
    }
}

pub fn set_config(config: Config) {
    IOHandle::current().do_io(|ctx| ctx.tcp.config = config)
}
