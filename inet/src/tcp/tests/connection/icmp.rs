use bytes_io::{Bytes, ToBytes};
use std::{
    io::{self, ErrorKind},
    net::{Ipv4Addr, SocketAddr},
};

use types::{
    icmpv4::{IcmpV4DestinationUnreachableCode, IcmpV4Packet, IcmpV4Type},
    ip::{Ipv4Flags, Ipv4Packet},
    tcp::{TcpFlags, TcpPacket},
    udp::PROTO_UDP,
};

use crate::tcp::{PROTO_TCP, State};

use super::{TcpTestUnit, WIN_4KB};

impl TcpTestUnit {
    pub fn icmp_v4_with(&mut self, typ: IcmpV4Type, pkt: &Ipv4Packet) -> io::Result<()> {
        if let Some(ref mut con) = self.con {
            con.on_icmp_v4(&IcmpV4Packet::new(typ, pkt), pkt)
        } else {
            Ok(())
        }
    }

    pub fn icmp_v4(&mut self, icmp: IcmpV4Type) -> io::Result<()> {
        if let Some(ref mut con) = self.con {
            let contained = Ipv4Packet {
                dscp: 0,
                enc: 0,
                identification: 0,
                flags: Ipv4Flags { df: true, mf: true },
                ttl: 64,
                fragment_offset: 0,
                proto: PROTO_TCP,
                src: Ipv4Addr::new(10, 0, 1, 104),
                dst: Ipv4Addr::new(20, 0, 2, 204),
                content: TcpPacket {
                    src_port: con.quad.src.port(),
                    dst_port: con.quad.dst.port(),
                    seq_no: 0,
                    ack_no: 0,
                    flags: TcpFlags::empty(),
                    window: 0,
                    urgent_ptr: 0,
                    options: Vec::new(),
                    content: Bytes::new(),
                }
                .write_to_bytes()
                .unwrap(),
            };

            con.on_icmp_v4(
                &IcmpV4Packet {
                    typ: icmp,
                    content: Bytes::new(),
                },
                &contained,
            )
        } else {
            Ok(())
        }
    }
}

#[test]
fn reduce_mss_caused_by_icmp_v6_packet_too_big() -> io::Result<()> {
    let mut test = TcpTestUnit::new(
        SocketAddr::new(Ipv4Addr::new(10, 0, 1, 104).into(), 80), // local
        SocketAddr::new(Ipv4Addr::new(20, 0, 2, 204).into(), 1808), // peer
    );
    test.cfg.mss = Some(1000);
    test.cfg.send_buffer_cap = 1000000;
    test.handshake(4000, WIN_4KB)?;

    assert_eq!(test.snd.mss, 1000);

    test.write(&[1; 4096])?;
    test.tick()?;
    test.assert_outgoing(|pkts| {
        pkts.iter()
            .rev()
            .skip(1)
            .for_each(|pkt| assert_eq!(pkt.content.len(), 1000))
    });

    test.change_mtu(800); // MSS + 20 + 20
    assert_eq!(test.snd.mss, 740);

    test.write(&[1; 4096])?;
    test.tick()?;
    test.assert_outgoing(|pkts| {
        pkts.iter()
            .rev()
            .skip(1)
            .for_each(|pkt| assert_eq!(pkt.content.len(), 740))
    });

    Ok(())
}

#[test]
fn demux_no_proto_tcp() -> io::Result<()> {
    let mut test = TcpTestUnit::new(
        SocketAddr::new(Ipv4Addr::new(10, 0, 1, 104).into(), 80), // local
        SocketAddr::new(Ipv4Addr::new(20, 0, 2, 204).into(), 1808), // peer
    );
    test.handshake(4000, WIN_4KB)?;

    test.icmp_v4_with(
        // would be hard error
        IcmpV4Type::DestinationUnreachable {
            next_hop_mtu: 0,
            code: IcmpV4DestinationUnreachableCode::PortUnreachable,
        },
        &Ipv4Packet {
            dscp: 0,
            enc: 0,
            identification: 0,
            flags: Ipv4Flags { df: true, mf: true },
            fragment_offset: 0,
            ttl: 64,
            proto: PROTO_UDP,
            src: Ipv4Addr::new(10, 0, 1, 104),
            dst: Ipv4Addr::new(20, 0, 2, 204),
            content: Bytes::from_static(&[1, 2, 3, 4, 5, 6, 7, 8]),
        },
    )?;
    assert_eq!(test.state, State::Estab);

    Ok(())
}

#[test]
fn demux_quad_missmatch() -> io::Result<()> {
    let mut test = TcpTestUnit::new(
        SocketAddr::new(Ipv4Addr::new(10, 0, 1, 104).into(), 80), // local
        SocketAddr::new(Ipv4Addr::new(20, 0, 2, 204).into(), 1808), // peer
    );
    test.handshake(4000, WIN_4KB)?;

    // Remote port missmatch
    test.icmp_v4_with(
        // would be hard error
        IcmpV4Type::DestinationUnreachable {
            next_hop_mtu: 0,
            code: IcmpV4DestinationUnreachableCode::PortUnreachable,
        },
        &Ipv4Packet {
            dscp: 0,
            enc: 0,
            identification: 0,
            flags: Ipv4Flags { df: true, mf: true },
            fragment_offset: 0,
            ttl: 64,
            proto: PROTO_TCP,
            src: Ipv4Addr::new(10, 0, 1, 104),
            dst: Ipv4Addr::new(20, 0, 2, 204),
            content: TcpPacket::new(80, 1801, 0, 0, 0, Vec::new()).write_to_bytes()?,
        },
    )?;
    assert_eq!(test.state, State::Estab);

    // Local port missmatch
    test.icmp_v4_with(
        // would be hard error
        IcmpV4Type::DestinationUnreachable {
            next_hop_mtu: 0,
            code: IcmpV4DestinationUnreachableCode::PortUnreachable,
        },
        &Ipv4Packet {
            dscp: 0,
            enc: 0,
            identification: 0,
            flags: Ipv4Flags { df: true, mf: true },
            fragment_offset: 0,
            ttl: 64,
            proto: PROTO_TCP,
            src: Ipv4Addr::new(10, 0, 1, 104),
            dst: Ipv4Addr::new(20, 0, 2, 204),
            content: TcpPacket::new(81, 1808, 0, 0, 0, Vec::new()).write_to_bytes()?,
        },
    )?;
    assert_eq!(test.state, State::Estab);

    // Local IP missmatch
    test.icmp_v4_with(
        // would be hard error
        IcmpV4Type::DestinationUnreachable {
            next_hop_mtu: 0,
            code: IcmpV4DestinationUnreachableCode::PortUnreachable,
        },
        &Ipv4Packet {
            dscp: 0,
            enc: 0,
            identification: 0,
            flags: Ipv4Flags { df: true, mf: true },
            fragment_offset: 0,
            ttl: 64,
            proto: PROTO_TCP,
            src: Ipv4Addr::new(10, 0, 1, 105),
            dst: Ipv4Addr::new(20, 0, 2, 204),
            content: TcpPacket::new(80, 1808, 0, 0, 0, Vec::new()).write_to_bytes()?,
        },
    )?;
    assert_eq!(test.state, State::Estab);

    Ok(())
}

#[test]
fn dst_unreachable_hard_on_syn_snt() -> io::Result<()> {
    let mut test = TcpTestUnit::new(
        SocketAddr::new(Ipv4Addr::new(10, 0, 1, 104).into(), 80), // local
        SocketAddr::new(Ipv4Addr::new(20, 0, 2, 204).into(), 1808), // peer
    );

    test.connect()?;
    test.assert_outgoing_eq(&[TcpPacket::syn(80, 1808, 0, WIN_4KB)]);

    test.icmp_v4(IcmpV4Type::DestinationUnreachable {
        next_hop_mtu: 0,
        code: IcmpV4DestinationUnreachableCode::ProtocolUnreachable,
    })?;
    assert_eq!(test.state, State::Closed);
    assert_eq!(
        test.interface.error.as_ref().map(|v| v.kind()),
        Some(ErrorKind::ConnectionReset)
    );

    Ok(())
}

#[test]
fn dst_unreachable_hard_on_syn_rcvd() -> io::Result<()> {
    let mut test = TcpTestUnit::new(
        SocketAddr::new(Ipv4Addr::new(10, 0, 1, 104).into(), 80), // local
        SocketAddr::new(Ipv4Addr::new(20, 0, 2, 204).into(), 1808), // peer
    );

    test.incoming(TcpPacket::syn(1808, 80, 4001, WIN_4KB))?;
    test.assert_outgoing_eq(&[TcpPacket::syn_ack(
        &TcpPacket::syn(1808, 80, 4001, WIN_4KB),
        0,
        WIN_4KB,
    )]);

    test.icmp_v4(IcmpV4Type::DestinationUnreachable {
        next_hop_mtu: 0,
        code: IcmpV4DestinationUnreachableCode::ProtocolUnreachable,
    })?;
    assert_eq!(test.state, State::Closed);
    assert_eq!(
        test.interface.error.as_ref().map(|v| v.kind()),
        Some(ErrorKind::ConnectionReset)
    );

    Ok(())
}

#[test]
fn dst_unreachable_hard_on_estab_like() -> io::Result<()> {
    let mut test = TcpTestUnit::new(
        SocketAddr::new(Ipv4Addr::new(10, 0, 1, 104).into(), 80), // local
        SocketAddr::new(Ipv4Addr::new(20, 0, 2, 204).into(), 1808), // peer
    );

    test.connect()?;

    test.icmp_v4(IcmpV4Type::DestinationUnreachable {
        next_hop_mtu: 0,
        code: IcmpV4DestinationUnreachableCode::ProtocolUnreachable,
    })?;
    assert_eq!(test.state, State::Closed);
    assert_eq!(
        test.interface.error.as_ref().map(|v| v.kind()),
        Some(ErrorKind::ConnectionReset)
    );

    Ok(())
}

#[test]
fn dst_unreachable_hard_on_close_like() -> io::Result<()> {
    let mut test = TcpTestUnit::new(
        SocketAddr::new(Ipv4Addr::new(10, 0, 1, 104).into(), 80), // local
        SocketAddr::new(Ipv4Addr::new(20, 0, 2, 204).into(), 1808), // peer
    );

    test.handshake(4000, WIN_4KB)?;

    test.close()?;
    test.tick()?;
    test.clear_outgoing();

    test.incoming(TcpPacket::new(1808, 80, 4001, 1, WIN_4KB, Vec::new()).fin(true))?;
    test.clear_outgoing();
    assert_eq!(test.state, State::Closing);

    test.icmp_v4(IcmpV4Type::DestinationUnreachable {
        next_hop_mtu: 0,
        code: IcmpV4DestinationUnreachableCode::ProtocolUnreachable,
    })?;
    assert_eq!(test.state, State::Closed);

    Ok(())
}
