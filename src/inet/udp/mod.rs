use super::{Fd, IOContext, SocketDomain, SocketType};
use crate::{
    inet::InterfaceStatus,
    ip::{IPFlags, IPPacket, IPVersion},
    FromBytestream, IntoBytestream,
};
use std::{
    collections::VecDeque,
    io::{Error, ErrorKind, Result},
    net::{IpAddr, SocketAddr},
};

mod pkt;
use des::prelude::GateRef;
pub use pkt::*;

mod socket;
pub use socket::*;

mod interest;
use interest::*;

pub(super) const PROTO_UDP: u8 = 0x11;

pub(super) struct UdpManager {
    pub(super) local_addr: SocketAddr,
    pub(super) state: UdpSocketState,
    pub(super) incoming: VecDeque<(SocketAddr, SocketAddr, UDPPacket)>,

    pub(super) ttl: u8,
    pub(super) broadcast: bool,

    pub(super) interest: Option<UdpInterestGuard>,
}

impl UdpManager {
    // pub(self) fn info(&self) -> UdpSocketInfo {
    //     UdpSocketInfo {
    //         addr: self.local_addr,
    //         peer: self.state.peer(),
    //         in_queue_size: self.incoming.len(),
    //     }
    // }

    pub(self) fn ip_version(&self) -> IPVersion {
        let v4 =
            self.local_addr.is_ipv4() && self.state.peer().map(|p| p.is_ipv4()).unwrap_or(false);
        if v4 {
            IPVersion::V4
        } else {
            IPVersion::V6
        }
    }
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

impl UdpSocketState {
    pub(self) fn peer(&self) -> Option<SocketAddr> {
        match self {
            Self::Bound => None,
            Self::Connected(addr) => Some(*addr),
        }
    }
}

impl IOContext {
    // returns consumed
    pub(super) fn capture_udp_packet(
        &mut self,
        packet: &IPPacket,
        last_gate: Option<GateRef>,
    ) -> bool {
        assert_eq!(packet.proto, PROTO_UDP);

        if packet.dest.is_broadcast() {
            return self.capture_udp_packet_broadcast(packet, last_gate);
        }

        let Ok(udp) = UDPPacket::from_buffer(&packet.content) else {
            log::error!("received ip-packet with proto=0x11 (udp) but content was no udp-packet");
            return false;
        };

        let src = SocketAddr::new(IpAddr::V4(packet.src), udp.src_port);
        let dest = SocketAddr::new(IpAddr::V4(packet.dest), udp.dest_port);

        let Some(ifid) = self.capture_udp_get_interface(IpAddr::V4(packet.dest), last_gate).pop() else {
            return false
        };

        let Some((fd, udp_handle)) = self.udp_manager.iter_mut().find(|(_, socket)| socket.local_addr == dest) else {
            return false
        };

        let socket = self.sockets.get(fd).expect("underlying os socket dropped");

        if socket.interface != ifid {
            return false;
        }

        udp_handle.incoming.push_back((src, dest, udp));
        if let Some(interest) = &udp_handle.interest {
            if interest.interest.interest.is_readable() {
                udp_handle.interest.take().unwrap().waker.wake();
            }
        }

        true
    }

    fn capture_udp_packet_broadcast(
        &mut self,
        packet: &IPPacket,
        last_gate: Option<GateRef>,
    ) -> bool {
        let Ok(udp) = UDPPacket::from_buffer(&packet.content) else {
            log::error!("received ip-packet with proto=0x11 (udp) but content was no udp-packet");
            return false;
        };

        let src = SocketAddr::new(IpAddr::V4(packet.src), udp.src_port);
        let dest = SocketAddr::new(IpAddr::V4(packet.dest), udp.dest_port);

        for ifid in self.capture_udp_get_interface(IpAddr::V4(packet.dest), last_gate) {
            let Some((fd, udp_handle)) = self.udp_manager.iter_mut().find(|(_, socket)| socket.local_addr.port() == udp.dest_port) else {
                continue
            };

            let socket = self.sockets.get(fd).expect("underlying os socket dropped");
            if socket.interface != ifid {
                continue;
            }

            udp_handle.incoming.push_back((src, dest, udp.clone()));
            if let Some(interest) = &udp_handle.interest {
                if interest.interest.interest.is_readable() {
                    udp_handle.interest.take().unwrap().waker.wake();
                }
            }
        }
        false
    }

    fn capture_udp_get_interface(&self, ip: IpAddr, last_gate: Option<GateRef>) -> Vec<u64> {
        let mut ifaces = self
            .interfaces
            .iter()
            .filter(|(_, iface)| iface.status == InterfaceStatus::Active && iface.flags.up)
            .filter(|(_, iface)| iface.last_gate_matches(&last_gate))
            .filter(|(_, iface)| iface.addrs.iter().any(|addr| addr.matches_ip(ip)))
            .collect::<Vec<_>>();

        ifaces.sort_by(|(_, l), (_, r)| r.prio.cmp(&l.prio));

        ifaces.into_iter().map(|v| *v.0).collect::<Vec<_>>()
    }
}

impl IOContext {
    pub(super) fn udp_bind(&mut self, addr: SocketAddr) -> Result<UdpSocket> {
        let domain = if addr.is_ipv4() {
            SocketDomain::AF_INET
        } else {
            SocketDomain::AF_INET6
        };

        let socket: Fd = self.posix_create_socket(domain, SocketType::SOCK_DGRAM, 0);

        let baddr = self.posix_bind_socket(socket, addr).map_err(|e| {
            self.posix_close_socket(socket);
            e
        })?;

        let manager = UdpManager {
            local_addr: baddr,
            state: UdpSocketState::Bound,
            incoming: VecDeque::new(),

            ttl: 32,
            broadcast: false,

            interest: None,
        };
        self.udp_manager.insert(socket, manager);

        Ok(UdpSocket { fd: socket })
    }

    pub(super) fn udp_local_addr(&mut self, socket: Fd) -> Result<SocketAddr> {
        match self.udp_manager.get(&socket) {
            Some(v) => Ok(v.local_addr),
            None => Err(Error::new(ErrorKind::Other, "Invalid FD")),
        }
    }

    pub(super) fn udp_peer_addr(&mut self, socket: Fd) -> Result<SocketAddr> {
        let Some(socket) = self.udp_manager.get(&socket) else {
            return Err(Error::new(ErrorKind::InvalidInput, "invalid fd - socket dropped"))
        };
        match socket.state.peer() {
            Some(v) => Ok(v),
            None => Err(Error::new(
                ErrorKind::Other,
                "no peer address associated with socket",
            )),
        }
    }

    pub(super) fn udp_connect(&mut self, socket: Fd, peer: SocketAddr) -> Result<()> {
        let Some(socket) = self.udp_manager.get_mut(&socket) else {
            return Err(Error::new(ErrorKind::InvalidInput, "invalid fd - socket dropped"))
        };

        socket.state = UdpSocketState::Connected(peer);
        Ok(())
    }

    pub(super) fn udp_send_to(&mut self, fd: Fd, target: SocketAddr, buf: &[u8]) -> Result<usize> {
        let Some(socket) = self.udp_manager.get(&fd) else {
            return Err(Error::new(ErrorKind::InvalidInput, "invalid fd - socket dropped"))
        };

        // (1.1) Check version match
        if socket.local_addr.is_ipv4() != target.is_ipv4() {
            return Err(Error::new(ErrorKind::InvalidInput, "ip version missmatch"));
        }

        // (1.2) Check Broadcast
        if let IpAddr::V4(dest_addr) = target.ip() {
            if dest_addr.is_broadcast() && !socket.broadcast {
                return Err(Error::new(
                    ErrorKind::Other,
                    "cannot send broadcast without broadcast flag enabled",
                ));
            }
        }

        let udp_packet = UDPPacket {
            src_port: socket.local_addr.port(),
            dest_port: target.port(),
            checksum: 0,
            content: Vec::from(buf),
        };

        let content = udp_packet.into_buffer()?;

        match (socket.local_addr.ip(), target.ip()) {
            (IpAddr::V4(local), IpAddr::V4(target)) => {
                let ip = IPPacket {
                    version: socket.ip_version(),
                    dscp: 0,
                    enc: 0,
                    identification: 0,
                    flags: IPFlags {
                        df: false,
                        mf: false,
                    },
                    fragment_offset: 0,
                    ttl: socket.ttl,
                    proto: PROTO_UDP,

                    src: local,
                    dest: target,

                    checksum: 0,
                    content,
                };

                let socket_info = self
                    .sockets
                    .get(&fd)
                    .expect("Socket should not have been dropped");

                let Some(interface) = self.interfaces.get_mut(&socket_info.interface) else {
                    return Err(Error::new(ErrorKind::Other, "interface down"))
                };

                interface.send_ip(ip)?;
                Ok(buf.len())
            }
            (IpAddr::V6(_), IpAddr::V6(_)) => Ok(buf.len()),
            _ => unreachable!(),
        }
    }

    pub(super) fn udp_drop(&mut self, fd: Fd) {
        self.udp_manager.remove(&fd);
        self.posix_close_socket(fd);
    }
}
