//! The User Datagram Protocol (UDP)
use super::{socket::*, IOContext};
use crate::interface::IfId;
use bytepack::{FromBytestream, ToBytestream};
use fxhash::{FxBuildHasher, FxHashMap};
use std::{
    collections::VecDeque,
    io::{Error, ErrorKind, Result},
    net::{IpAddr, SocketAddr},
};
use types::{
    ip::{IpPacket, IpPacketRef, Ipv4Flags, Ipv4Packet, Ipv6Packet},
    udp::{UdpPacket, PROTO_UDP},
};

mod api;
pub use api::*;

mod interest;
use interest::*;

pub(super) struct Udp {
    pub(super) binds: FxHashMap<Fd, UdpControlBlock>,
}

impl Udp {
    pub(super) fn new() -> Udp {
        Udp {
            binds: FxHashMap::with_hasher(FxBuildHasher::default()),
        }
    }
}

pub(super) struct UdpControlBlock {
    pub(super) local_addr: SocketAddr,
    pub(super) state: UdpSocketState,
    pub(super) incoming: VecDeque<(SocketAddr, SocketAddr, UdpPacket)>,

    pub(super) ttl: u8,
    pub(super) broadcast: bool,

    pub(super) error: Option<Error>,
    pub(super) interest: Option<UdpInterestGuard>,
}

/// A public info over UDP sockets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdpSocketInfo {
    /// The address the socket is bound to
    pub addr: SocketAddr,
    /// The peer socket if one was defined.
    pub peer: Option<SocketAddr>,
    /// The number of waiting packets
    pub in_queue_size: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub(super) enum UdpSocketState {
    #[default]
    Bound,
    Connected(SocketAddr),
}

impl UdpControlBlock {
    pub(super) fn push_incoming(&mut self, src: SocketAddr, dest: SocketAddr, udp: UdpPacket) {
        self.incoming.push_back((src, dest, udp));
        if let Some(interest) = &self.interest {
            if interest.is_readable() {
                self.interest.take().unwrap().wake();
            }
        }
    }
}

fn is_broadcast(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_broadcast(),
        _ => false,
    }
}

fn is_valid_dest_for(socket_addr: &SocketAddr, packet_addr: &SocketAddr) -> bool {
    if socket_addr.ip().is_unspecified() {
        return socket_addr.port() == packet_addr.port();
    }

    match packet_addr {
        SocketAddr::V4(addrv4) => {
            if addrv4.ip().is_broadcast() {
                return socket_addr.port() == addrv4.port();
            }
            socket_addr == packet_addr
        }
        SocketAddr::V6(_) => socket_addr == packet_addr,
    }
}

impl IOContext {
    // returns consumed
    pub(super) fn recv_udp_packet(&mut self, packet: IpPacketRef, ifid: IfId) -> bool {
        assert_eq!(packet.tos(), PROTO_UDP);

        let is_broadcast = is_broadcast(packet.dest());

        let Ok(udp) = UdpPacket::from_slice(packet.content()) else {
            tracing::error!(
                "received ip-packet with proto=0x11 (udp) but content was no udp-packet"
            );
            return false;
        };

        let src = SocketAddr::new(packet.src(), udp.src_port);
        let dest = SocketAddr::new(packet.dest(), udp.dst_port);

        let mut iter = self.sockets.iter_mut().filter(|(_, sock)| {
            sock.typ == SocketType::SOCK_DGRAM && is_valid_dest_for(&sock.addr, &dest)
        });

        if is_broadcast {
            let mut recvd = false;
            for (fd, sock) in iter {
                sock.recv_q += udp.content.len();

                let Some(mng) = self.udp.binds.get_mut(fd) else {
                    tracing::error!("found udp socket, but missing udp manager");
                    return false;
                };

                mng.push_incoming(src, dest, udp.clone());
                recvd = true;
            }
            recvd
        } else {
            let Some((fd, sock)) = iter.next() else {
                self.icmp_port_unreachable(ifid, packet);
                return false;
            };
            if !sock.interface.contains(&ifid) {
                tracing::error!("interface missmatch");
                return false;
            }

            sock.recv_q += udp.content.len();

            let Some(mng) = self.udp.binds.get_mut(fd) else {
                tracing::error!("found udp socket, but missing udp manager");
                return false;
            };

            mng.push_incoming(src, dest, udp);
            true
        }
    }

    pub(super) fn udp_icmp_error(&mut self, fd: Fd, e: Error, ip: IpPacket) {
        let Some(mng) = self.udp.binds.get_mut(&fd) else {
            return;
        };

        let UdpSocketState::Connected(addr) = mng.state else {
            return;
        };

        if ip.dst() == addr.ip() {
            // TTL execeeded is correct
            let _ = mng.error.replace(e);
        }
    }
}

impl IOContext {
    pub(super) fn udp_bind(&mut self, addr: SocketAddr) -> Result<UdpSocket> {
        let domain = if addr.is_ipv4() {
            SocketDomain::AF_INET
        } else {
            SocketDomain::AF_INET6
        };

        let socket: Fd = self.create_socket(domain, SocketType::SOCK_DGRAM, 0)?;

        let baddr = self.bind_socket(socket, addr).map_err(|e| {
            let _ = self.close_socket(socket);
            e
        })?;

        let manager = UdpControlBlock {
            local_addr: baddr,
            state: UdpSocketState::Bound,
            incoming: VecDeque::new(),

            ttl: 32,
            broadcast: false,
            error: None,

            interest: None,
        };
        self.udp.binds.insert(socket, manager);

        Ok(UdpSocket { fd: socket })
    }

    pub(super) fn udp_connect(&mut self, fd: Fd, peer: SocketAddr) -> Result<()> {
        let Some(socket) = self.udp.binds.get_mut(&fd) else {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "invalid fd - socket dropped",
            ));
        };

        socket.state = UdpSocketState::Connected(peer);
        self.bind_peer(fd, peer)?;
        Ok(())
    }

    pub(super) fn udp_send_to(&mut self, fd: Fd, target: SocketAddr, buf: &[u8]) -> Result<usize> {
        let Some(mng) = self.udp.binds.get_mut(&fd) else {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "invalid fd - socket dropped",
            ));
        };

        // (1.1) Check version match
        if mng.local_addr.is_ipv4() != target.is_ipv4() {
            return Err(Error::new(ErrorKind::InvalidInput, "ip version missmatch"));
        }

        // (1.2) Check Broadcast
        if let IpAddr::V4(dest_addr) = target.ip() {
            if dest_addr.is_broadcast() && !mng.broadcast {
                return Err(Error::new(
                    ErrorKind::Other,
                    "cannot send broadcast without broadcast flag enabled",
                ));
            }
        }

        if target.ip().is_unspecified() {
            panic!()
        }

        let udp_packet = UdpPacket {
            src_port: mng.local_addr.port(),
            dst_port: target.port(),
            checksum: 0,
            content: Vec::from(buf),
        };
        let content = udp_packet.to_vec()?;

        match (mng.local_addr.ip(), target.ip()) {
            (IpAddr::V4(local), IpAddr::V4(target)) => {
                let ip = Ipv4Packet {
                    dscp: 0,
                    enc: 0,
                    identification: 0,
                    flags: Ipv4Flags {
                        df: false,
                        mf: false,
                    },
                    fragment_offset: 0,
                    ttl: mng.ttl,
                    proto: PROTO_UDP,

                    src: local,
                    dst: target,

                    content,
                };

                let socket_info = self
                    .sockets
                    .get_mut(&fd)
                    .expect("Socket should not have been dropped");
                socket_info.send_q += buf.len();

                let ifid = socket_info.interface.clone();

                self.send_ip_packet(ifid, IpPacket::V4(ip), true)?;
                Ok(buf.len())
            }
            (IpAddr::V6(local), IpAddr::V6(target)) => {
                let ip = Ipv6Packet {
                    traffic_class: 0,
                    flow_label: 0,
                    next_header: PROTO_UDP,
                    hop_limit: 128,

                    src: local,
                    dst: target,

                    content,
                };

                let socket_info = self
                    .sockets
                    .get_mut(&fd)
                    .expect("Socket should not have been dropped");
                socket_info.send_q += buf.len();

                let ifid = socket_info.interface.clone();

                self.send_ip_packet(ifid, IpPacket::V6(ip), true)?;
                Ok(buf.len())
            }
            _ => unreachable!(),
        }
    }

    fn udp_take_error(&mut self, fd: Fd) -> Result<Option<Error>> {
        let Some(mng) = self.udp.binds.get_mut(&fd) else {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "invalid fd - socket dropped",
            ));
        };

        Ok(mng.error.take())
    }

    pub(super) fn udp_drop(&mut self, fd: Fd) {
        self.udp.binds.remove(&fd);
        let _ = self.close_socket(fd);
    }
}
