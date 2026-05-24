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
use std::{
    io::{self, Error, ErrorKind},
    net::{IpAddr, Ipv4Addr},
};

use bytes_io::{FromBytes, ToBytes};
use types::{
    icmpv4::{
        IcmpV4DestinationUnreachableCode, IcmpV4Packet, IcmpV4TimeExceededCode, IcmpV4Type,
        PROTO_ICMPV4,
    },
    ip::{IpPacket, Ipv4Flags, Ipv4Packet},
    tcp::PROTO_TCP,
    udp::PROTO_UDP,
};

use crate::{
    IOContext,
    interface::{IfId, IfSpec},
    socket::{SocketDomain, SocketType},
};

impl IOContext {
    pub fn ipv4_icmp_recv(&mut self, ip_icmp: &Ipv4Packet, ifid: IfId) -> bool {
        assert_eq!(ip_icmp.proto, PROTO_ICMPV4);

        let Ok(pkt) = IcmpV4Packet::peek_from(&ip_icmp.content[..]) else {
            tracing::error!(
                "received ip-packet with proto=0x1 (icmpv4) but content was no icmpv4-packet"
            );
            return false;
        };

        let contained = pkt
            .contained()
            .expect("failed to unwrap ip packet contained in icmp");

        // Transport layer mplex bypass
        use SocketDomain::*;
        use SocketType::*;

        let affected_sockets = self
            .sockets
            .iter()
            .filter(|s| s.1.peer.ip() == IpAddr::V4(contained.dst) && s.1.domain == AF_INET)
            .map(|(fd, sock)| (*fd, sock.typ))
            .collect::<Vec<_>>();

        for (fd, socket_typ) in affected_sockets {
            match (socket_typ, contained.proto) {
                (SOCK_STREAM, PROTO_TCP) => self.tcp_on_icmpv4(fd, &pkt, &contained),
                (SOCK_DGRAM, PROTO_UDP) => self.udp_icmp_error(
                    fd,
                    Error::new(ErrorKind::ConnectionRefused, pkt.typ.as_error_string()),
                    IpPacket::V4(contained.clone()),
                ),
                (SOCK_RAW, _) => self.ipv4_raw_socket_on_icmp(ifid, fd, &pkt, &contained),
                _ => {}
            }
        }

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
                    content: icmp.write_to_bytes().expect("Failed to parse ICMP"),
                };
                self.ipv4_send(Some(ifid), ip).expect("Failed to send");
            }
            IcmpV4Type::EchoReply { .. } => {}
            IcmpV4Type::DestinationUnreachable { .. } => {
                return true;
            }
            IcmpV4Type::TimeExceeded { code } => {
                let ip = pkt.contained().unwrap();
                let unreachable = ip.dst;

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
                                Error::other(format!("{code:?}")),
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

    pub fn ipv4_icmp_routing_failed(&mut self, e: Error, pkt: &Ipv4Packet) {
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
                ip.content = icmp.write_to_bytes().expect("Failed to parse ICMP");

                self.ipv4_send(None, ip).unwrap()
            }
            ErrorKind::NotConnected => self
                .ipv4_icmp_send_destionation_unreachable(
                    IcmpV4DestinationUnreachableCode::HostUnreachable,
                    None,
                    pkt,
                )
                .expect("failed to send"),
            _ => {}
        }
    }

    pub fn ipv4_icmp_send_destionation_unreachable(
        &mut self,
        code: IcmpV4DestinationUnreachableCode,
        ifspec: IfSpec,
        pkt: &Ipv4Packet,
    ) -> io::Result<()> {
        let icmp = IcmpV4Packet::new(
            IcmpV4Type::DestinationUnreachable {
                next_hop_mtu: 0,
                code,
            },
            pkt,
        );

        let mut ip = pkt.reverse();
        ip.src = Ipv4Addr::UNSPECIFIED;
        ip.proto = PROTO_ICMPV4;
        ip.content = icmp.write_to_bytes()?;

        self.ipv4_send(ifspec, ip)
    }

    pub fn ipv4_icmp_send_ttl_expired(&mut self, ifid: IfId, pkt: &Ipv4Packet) -> io::Result<()> {
        if self.ipv4.cfg.no_icmp_responses {
            return Ok(());
        }

        let icmp = IcmpV4Packet::new(
            IcmpV4Type::TimeExceeded {
                code: IcmpV4TimeExceededCode::TimeToLifeInTransit,
            },
            pkt,
        );
        let mut ip = pkt.reverse();
        ip.src = Ipv4Addr::UNSPECIFIED;
        ip.proto = PROTO_ICMPV4;
        ip.content = icmp.write_to_bytes()?;
        self.ipv4_send(Some(ifid), ip)
    }

    pub fn ipv4_icmp_port_unreachable(&mut self, ifid: IfId, pkt: &Ipv4Packet) {
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
        ip.content = icmp.write_to_bytes().expect("Failed to parse ICMP");
        self.ipv4_send(Some(ifid), ip).unwrap();
    }
}
