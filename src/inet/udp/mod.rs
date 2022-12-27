use super::{Fd, IOContext, SocketDomain, SocketType};
use crate::{
    ip::{IpFlags, IpPacket, IpPacketRef, IpVersion, Ipv4Packet, Ipv6Packet},
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

    pub(self) fn ip_version(&self) -> IpVersion {
        let v4 =
            self.local_addr.is_ipv4() && self.state.peer().map(|p| p.is_ipv4()).unwrap_or(false);
        if v4 {
            IpVersion::V4
        } else {
            IpVersion::V6
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
        packet: IpPacketRef,
        last_gate: Option<GateRef>,
    ) -> bool {
        assert_eq!(packet.tos(), PROTO_UDP);

        fn is_broadcast(ip: IpAddr) -> bool {
            match ip {
                IpAddr::V4(v4) => v4.is_broadcast(),
                _ => false,
            }
        }

        if is_broadcast(packet.dest()) {
            return self.capture_udp_packet_broadcast(packet, last_gate);
        }

        let Ok(udp) = UDPPacket::from_buffer(packet.content()) else {
            log::error!("received ip-packet with proto=0x11 (udp) but content was no udp-packet");
            return false;
        };

        let src = SocketAddr::new(packet.src(), udp.src_port);
        let dest = SocketAddr::new(packet.dest(), udp.dest_port);

        let Some(ifid) = self.get_interface_for_ip_packet(packet.dest(), last_gate).pop() else {
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
            if interest.is_readable() {
                udp_handle.interest.take().unwrap().wake();
            }
        }

        true
    }

    fn capture_udp_packet_broadcast(
        &mut self,
        packet: IpPacketRef,
        last_gate: Option<GateRef>,
    ) -> bool {
        let Ok(udp) = UDPPacket::from_buffer(packet.content()) else {
            log::error!("received ip-packet with proto=0x11 (udp) but content was no udp-packet");
            return false;
        };

        let src = SocketAddr::new(packet.src(), udp.src_port);
        let dest = SocketAddr::new(packet.dest(), udp.dest_port);

        for ifid in self.get_interface_for_ip_packet(packet.dest(), last_gate) {
            let Some((fd, udp_handle)) = self.udp_manager.iter_mut().find(|(_, socket)| socket.local_addr.port() == udp.dest_port) else {
                continue
            };

            let socket = self.sockets.get(fd).expect("underlying os socket dropped");
            if socket.interface != ifid {
                continue;
            }

            udp_handle.incoming.push_back((src, dest, udp.clone()));
            if let Some(interest) = &udp_handle.interest {
                if interest.is_readable() {
                    udp_handle.interest.take().unwrap().wake();
                }
            }
        }
        false
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

    pub(super) fn udp_connect(&mut self, fd: Fd, peer: SocketAddr) -> Result<()> {
        let Some(socket) = self.udp_manager.get_mut(&fd) else {
            return Err(Error::new(ErrorKind::InvalidInput, "invalid fd - socket dropped"))
        };

        socket.state = UdpSocketState::Connected(peer);
        self.posix_bind_peer(fd, peer)?;
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
                let ip = Ipv4Packet {
                    version: socket.ip_version(),
                    dscp: 0,
                    enc: 0,
                    identification: 0,
                    flags: IpFlags {
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

                interface.send_ip(IpPacket::V4(ip))?;
                Ok(buf.len())
            }
            (IpAddr::V6(local), IpAddr::V6(target)) => {
                let ip = Ipv6Packet {
                    version: socket.ip_version(),
                    traffic_class: 0,
                    flow_label: 0,
                    hop_limit: socket.ttl,

                    next_header: PROTO_UDP,

                    src: local,
                    dest: target,

                    content,
                };

                let socket_info = self
                    .sockets
                    .get(&fd)
                    .expect("Socket should not have been dropped");

                let Some(interface) = self.interfaces.get_mut(&socket_info.interface) else {
                    return Err(Error::new(ErrorKind::Other, "interface down"))
                };

                interface.send_ip(IpPacket::V6(ip))?;
                Ok(buf.len())
            }
            _ => unreachable!(),
        }
    }

    pub(super) fn udp_drop(&mut self, fd: Fd) {
        self.udp_manager.remove(&fd);
        self.posix_close_socket(fd);
    }
}
