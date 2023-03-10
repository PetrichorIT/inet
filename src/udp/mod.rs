use super::{socket::*, IOContext};
use crate::{
    interface::IfId,
    ip::{IpPacketRef, Ipv4Flags, Ipv4Packet},
    FromBytestream, IntoBytestream,
};
use std::{
    collections::VecDeque,
    io::{Error, ErrorKind, Result},
    net::{IpAddr, Ipv4Addr, SocketAddr},
};

mod pkt;
pub use pkt::*;

mod api;
pub use api::*;

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

impl UdpManager {
    pub(super) fn push_incoming(&mut self, src: SocketAddr, dest: SocketAddr, udp: UDPPacket) {
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

fn is_valid_dest_for(dest: &SocketAddr, addr: &SocketAddr) -> bool {
    match addr {
        SocketAddr::V4(addrv4) => {
            if addrv4.ip().is_broadcast() {
                return dest.port() == addrv4.port();
            }
            if dest.ip() == IpAddr::V4(Ipv4Addr::UNSPECIFIED) {
                return dest.port() == addrv4.port();
            }
            dest == addr
        }
        SocketAddr::V6(_) => dest == addr,
    }
}

impl IOContext {
    // returns consumed
    pub(super) fn recv_udp_packet(&mut self, packet: IpPacketRef, ifid: IfId) -> bool {
        assert_eq!(packet.tos(), PROTO_UDP);

        let is_broadcast = is_broadcast(packet.dest());

        let Ok(udp) = UDPPacket::from_buffer(packet.content()) else {
            log::error!(target: "inet/udp", "received ip-packet with proto=0x11 (udp) but content was no udp-packet");
            return false;
        };

        let src = SocketAddr::new(packet.src(), udp.src_port);
        let dest = SocketAddr::new(packet.dest(), udp.dest_port);

        let mut iter = self.sockets.iter_mut().filter(|(_, sock)| {
            sock.typ == SocketType::SOCK_DGRAM && is_valid_dest_for(&sock.addr, &dest)
        });

        if is_broadcast {
            let mut recvd = false;
            for (fd, sock) in iter {
                sock.recv_q += udp.content.len();

                let Some(mng) = self.udp_manager.get_mut(fd) else {
                    log::error!(target: "inet/udp", "found udp socket, but missing udp manager");
                    return false;
                };

                mng.push_incoming(src, dest, udp.clone());
                recvd = true;
            }
            recvd
        } else {
            let Some((fd, sock)) = iter.next() else {
                return false;
            };
            if !sock.interface.contains(&ifid) {
                log::error!(target: "inet/udp", "interface missmatch");
                return false;
            }

            sock.recv_q += udp.content.len();

            let Some(mng) = self.udp_manager.get_mut(fd) else {
                log::error!(target: "inet/udp", "found udp socket, but missing udp manager");
                return false;
            };

            mng.push_incoming(src, dest, udp);
            true
        }

        // let mut recved = false;
        // for ifid in self.get_interface_for_ip_packet(packet.dest(), last_gate) {
        //     // println!("{:#?}", self.sockets);
        //     // println!("{ifid} := {}", self.interfaces.get(&ifid).unwrap().name);
        //     // println!("dest = {dest} ifid = {ifid} is_loopback = {is_loopback}");

        //     let Some((fd, socket)) = self.sockets.iter_mut().find(
        //         |(_,v)| v.typ == SocketType::SOCK_DGRAM && v.addr.port() == dest.port() && if is_loopback { v.addr.is_ipv4() == dest.is_ipv4() } else { v.addr == dest && ifid == v.interface }
        //     ) else {
        //         continue;
        //     };
        //     socket.recv_q += udp.content.len();
        //     // println!("sock : {fd}");

        //     let Some(udp_mng) = self.udp_manager.get_mut(fd) else {
        //         log::error!(target: "inet/udp", "found udp socket, but missing udp manager");
        //         continue;
        //     };

        //     if is_broadcast {
        //         udp_mng.push_incoming(src, dest, udp.clone());
        //         recved = true;
        //         // continue
        //     } else {
        //         udp_mng.push_incoming(src, dest, udp);
        //         return true;
        //     }
        // }

        // recved
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
        self.bind_peer(fd, peer)?;
        Ok(())
    }

    pub(super) fn udp_send_to(&mut self, fd: Fd, target: SocketAddr, buf: &[u8]) -> Result<usize> {
        let Some(mng) = self.udp_manager.get_mut(&fd) else {
            return Err(Error::new(ErrorKind::InvalidInput, "invalid fd - socket dropped"))
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

        let udp_packet = UDPPacket {
            src_port: mng.local_addr.port(),
            dest_port: target.port(),
            checksum: 0,
            content: Vec::from(buf),
        };
        let content = udp_packet.into_buffer()?;

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
                    dest: target,

                    content,
                };

                let socket_info = self
                    .sockets
                    .get_mut(&fd)
                    .expect("Socket should not have been dropped");
                socket_info.send_q += buf.len();

                let ifid = socket_info.interface.clone();
                self.send_ipv4_packet(ifid, ip, true)?;
                Ok(buf.len())
            }
            (IpAddr::V6(_local), IpAddr::V6(_target)) => {
                // let ip = Ipv6Packet {
                //     traffic_class: 0,
                //     flow_label: 0,
                //     hop_limit: mng.ttl,

                //     next_header: PROTO_UDP,

                //     src: local,
                //     dest: target,

                //     content,
                // };

                // let socket_info = self
                //     .sockets
                //     .get_mut(&fd)
                //     .expect("Socket should not have been dropped");
                // socket_info.send_q += buf.len();

                // let Some(interface) = self.ifaces.get_mut(&socket_info.interface.unwrap_ifid()) else {
                //     return Err(Error::new(ErrorKind::Other, "interface down"))
                // };

                // interface.send_ip(IpPacket::V6(ip))?;
                // Ok(buf.len())
                todo!()
            }
            _ => unreachable!(),
        }
    }

    pub(super) fn udp_drop(&mut self, fd: Fd) {
        self.udp_manager.remove(&fd);
        let _ = self.close_socket(fd);
    }
}
