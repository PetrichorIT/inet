//! The Internet Control Message Protocol (ICMP)
//!
//! ICMP provides out-of-band debugging tools for IP
//! based networks. By default all Inet-Modules
//! allow and anwser as specificied in ICMP, but be
//! aware that this helpful complicance does not
//! represent realtity.
//!
//! This module provides some ICMP associated
//! utility function for network debugging.
use fxhash::{FxBuildHasher, FxHashMap};
use std::{
    io::{Error, ErrorKind},
    net::{IpAddr, Ipv4Addr},
};

use bytepack::{FromBytestream, ToBytestream};
use des::time::SimTime;
use inet_types::{
    icmpv4::{
        IcmpV4DestinationUnreachableCode, IcmpV4Packet, IcmpV4TimeExceededCode, IcmpV4Type,
        PROTO_ICMPV4,
    },
    ip::{IpPacket, IpPacketRef, Ipv4Flags, Ipv4Packet},
};

use self::ping::PingCB;
use crate::{interface::IfId, socket::SocketIfaceBinding, IOContext};

mod ping;
pub use self::ping::*;

mod traceroute;
pub use self::traceroute::*;

pub(crate) struct Icmp {
    pings: FxHashMap<u16, PingCB>,
    pub traceroutes: FxHashMap<Ipv4Addr, TracerouteCB>,
}

impl Icmp {
    pub fn new() -> Self {
        Self {
            pings: FxHashMap::with_hasher(FxBuildHasher::default()),
            traceroutes: FxHashMap::with_hasher(FxBuildHasher::default()),
        }
    }
}

impl IOContext {
    pub(super) fn recv_icmpv4_packet(&mut self, ip_icmp: &Ipv4Packet, ifid: IfId) -> bool {
        assert_eq!(ip_icmp.proto, PROTO_ICMPV4);

        let Ok(mut pkt) = IcmpV4Packet::read_from_slice(&mut &ip_icmp.content[..]) else {
            tracing::error!(
                "received ip-packet with proto=0x1 (icmpv4) but content was no icmpv4-packet"
            );
            return false;
        };

        match pkt.typ {
            IcmpV4Type::EchoRequest {
                identifier,
                sequence,
            } => {
                // (0) Respond echo request
                let icmp = IcmpV4Packet::new(
                    IcmpV4Type::EchoReply {
                        identifier,
                        sequence,
                    },
                    ip_icmp,
                );
                let ip = Ipv4Packet {
                    enc: ip_icmp.enc,
                    dscp: ip_icmp.dscp,
                    identification: ip_icmp.identification,
                    flags: Ipv4Flags {
                        df: true,
                        mf: false,
                    },
                    fragment_offset: 0,
                    ttl: 32,
                    proto: PROTO_ICMPV4,
                    src: ip_icmp.dst,
                    dst: ip_icmp.src,
                    content: icmp.to_vec().expect("Failed to parse ICMP"),
                };
                self.send_ip_packet(SocketIfaceBinding::Bound(ifid), IpPacket::V4(ip), true)
                    .expect("Failed to send");
            }
            IcmpV4Type::EchoReply {
                identifier,
                sequence,
            } => {
                let Some(ping) = self.icmp.pings.get_mut(&identifier) else {
                    tracing::warn!("missguided icmp echo reply");
                    return false;
                };

                assert_eq!(ping.addr, ip_icmp.src);

                let more = ping.recv_echo_reply(identifier, sequence);
                if more {
                    ping.current_seq_no += 1;
                    self.icmp_send_ping(ip_icmp.src, identifier, sequence + 1)
                } else {
                    self.icmp.pings.remove(&identifier);
                }
            }
            IcmpV4Type::DestinationUnreachable { next_hop_mtu, code } => {
                let ip = pkt.contained();
                let unreachable = ip.dst;

                // (0) check for recent pings
                if let Some((ident, ping)) =
                    self.icmp.pings.iter_mut().find(|p| p.1.addr == unreachable)
                {
                    ping.publish.take().map(|s| {
                        s.send(Err(Error::new(
                            ErrorKind::ConnectionRefused,
                            format!("{code:?}"),
                        )))
                    });

                    let ident = *ident;
                    self.icmp.pings.remove(&ident);
                    return true;
                };

                // (1) Check sockets
                if let Some((fd, socket)) = self
                    .sockets
                    .iter()
                    .find(|s| s.1.peer.ip() == IpAddr::V4(unreachable))
                {
                    use crate::socket::SocketDomain::*;
                    use crate::socket::SocketType::*;

                    match (socket.domain, socket.typ) {
                        (AF_INET, SOCK_STREAM) => self.tcp_icmp_destination_unreachable(
                            *fd,
                            Error::new(ErrorKind::ConnectionRefused, format!("{code:?}")),
                        ),
                        (AF_INET, SOCK_DGRAM) => self.udp_icmp_error(
                            *fd,
                            Error::new(ErrorKind::ConnectionRefused, format!("{code:?}")),
                            IpPacket::V4(ip),
                        ),
                        _ => todo!(),
                    }

                    return true;
                }

                let _ = next_hop_mtu;
            }
            IcmpV4Type::TimeExceeded { code } => {
                let ip = pkt.contained();
                let unreachable = ip.dst;

                if let Some(trace) = self.icmp.traceroutes.get_mut(&unreachable) {
                    let dur = SimTime::now() - trace.last_send;
                    let _ = trace.recent_err.replace((ip_icmp.src, dur));
                    // Contimue to let UDP socket handlers forward the error
                }

                // (0) Check sockets
                if let Some((fd, socket)) = self
                    .sockets
                    .iter()
                    .find(|s| s.1.peer.ip() == IpAddr::V4(unreachable))
                {
                    use crate::socket::SocketDomain::*;
                    use crate::socket::SocketType::*;

                    match (socket.domain, socket.typ) {
                        (AF_INET, SOCK_STREAM) => todo!(),
                        (AF_INET, SOCK_DGRAM) => {
                            self.udp_icmp_error(
                                *fd,
                                Error::new(ErrorKind::Other, format!("{code:?}")),
                                IpPacket::V4(ip),
                            );
                        }
                        _ => todo!(),
                    }

                    return true;
                }

                //
            }
            _ => todo!(),
        }

        true
    }

    pub(super) fn icmp_routing_failed(&mut self, e: Error, pkt: &Ipv4Packet) {
        match e.kind() {
            ErrorKind::ConnectionRefused => {
                // Gateway error
                let icmp = IcmpV4Packet::new(
                    IcmpV4Type::DestinationUnreachable {
                        next_hop_mtu: 0,
                        code: IcmpV4DestinationUnreachableCode::NetworkUnreachable,
                    },
                    pkt,
                );

                let mut ip = pkt.reverse();
                ip.src = Ipv4Addr::UNSPECIFIED;
                ip.proto = PROTO_ICMPV4;
                ip.content = icmp.to_vec().expect("Failed to parse ICMP");

                self.send_ip_packet(SocketIfaceBinding::NotBound, IpPacket::V4(ip), true)
                    .unwrap()
            }
            ErrorKind::NotConnected => {
                // Gateway error
                let icmp = IcmpV4Packet::new(
                    IcmpV4Type::DestinationUnreachable {
                        next_hop_mtu: 0,
                        code: IcmpV4DestinationUnreachableCode::HostUnreachable,
                    },
                    pkt,
                );

                let mut ip = pkt.reverse();
                ip.src = Ipv4Addr::UNSPECIFIED;
                ip.proto = PROTO_ICMPV4;
                ip.content = icmp.to_vec().expect("Failed to parse ICMP");

                let _ = self.send_ip_packet(SocketIfaceBinding::NotBound, IpPacket::V4(ip), true);
            }
            _ => {}
        }
    }

    pub(super) fn icmp_ttl_expired(&mut self, ifid: IfId, pkt: &Ipv4Packet) {
        let icmp = IcmpV4Packet::new(
            IcmpV4Type::TimeExceeded {
                code: IcmpV4TimeExceededCode::TimeToLifeInTransit,
            },
            pkt,
        );
        let mut ip = pkt.reverse();
        ip.src = Ipv4Addr::UNSPECIFIED;
        ip.proto = PROTO_ICMPV4;
        ip.content = icmp.to_vec().expect("Failed to parse ICMP");
        self.send_ip_packet(SocketIfaceBinding::Bound(ifid), IpPacket::V4(ip), true)
            .unwrap();
    }

    pub(super) fn icmp_port_unreachable(&mut self, ifid: IfId, pkt: IpPacketRef) {
        if let IpPacketRef::V4(pkt) = pkt {
            let icmp = IcmpV4Packet::new(
                IcmpV4Type::DestinationUnreachable {
                    next_hop_mtu: 0,
                    code: IcmpV4DestinationUnreachableCode::PortUnreachable,
                },
                pkt,
            );
            let mut ip = pkt.reverse();
            ip.src = Ipv4Addr::UNSPECIFIED;
            ip.proto = PROTO_ICMPV4;
            ip.content = icmp.to_vec().expect("Failed to parse ICMP");
            self.send_ip_packet(SocketIfaceBinding::Bound(ifid), IpPacket::V4(ip), true)
                .unwrap();
        }
    }
}
