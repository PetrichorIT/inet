use crate::{
    interface::IfId,
    tcp2::{
        tests::{TcpTestUnit, WIN_4KB},
        Config,
    },
};
use bytepack::ToBytestream;
use types::{
    ip::{Ipv4Flags, Ipv4Packet, KIND_IPV4},
    tcp::{TcpPacket, PROTO_TCP},
};
use pcapng::{BlockWriter, InterfaceDescriptionOption, Linktype, TestBlockWriter};
use std::{
    io::{self, Cursor},
    net::{Ipv4Addr, SocketAddr},
};

#[test]
fn transmitt_data_after_handshake() -> io::Result<()> {
    let mut test = TcpTestUnit::new(
        SocketAddr::new(Ipv4Addr::new(10, 0, 1, 104).into(), 80),
        SocketAddr::new(Ipv4Addr::new(20, 0, 2, 204).into(), 1808),
    );

    test.handshake(4000, 1024)?;

    assert_eq!(test.write(&[1, 2, 3, 4, 5, 6, 7, 8])?, 8);
    test.tick()?;
    test.assert_outgoing_eq(&[TcpPacket::new(
        80,
        1808,
        1,
        4001,
        WIN_4KB,
        vec![1, 2, 3, 4, 5, 6, 7, 8],
    )]);

    assert_eq!(test.write(&[8, 7, 6, 5, 4, 3, 2, 1])?, 8);
    test.tick()?;
    test.assert_outgoing_eq(&[TcpPacket::new(
        80,
        1808,
        1 + 8,
        4001,
        WIN_4KB,
        vec![8, 7, 6, 5, 4, 3, 2, 1],
    )]);

    Ok(())
}

#[test]
fn tx_limited_by_peers_recv_window() -> io::Result<()> {
    let mut test = TcpTestUnit::new(
        SocketAddr::new(Ipv4Addr::new(10, 0, 1, 104).into(), 80),
        SocketAddr::new(Ipv4Addr::new(20, 0, 2, 204).into(), 1808),
    );
    test.cfg(Config {
        send_buffer_cap: 4 * 1024,
        recv_buffer_cap: 1024,
        mss: Some(1400),
        ..Default::default()
    });

    test.handshake(4000, 1024)?;

    let data: Vec<u8> = (0..).map(|v| (v % 256) as u8).take(4 * 1024).collect();

    assert_eq!(test.write(&data)?, 4 * 1024);
    test.tick()?;
    test.assert_outgoing_eq(&[TcpPacket::new(
        80,
        1808,
        1,
        4001,
        1024,
        data[..1024].to_vec(),
    )]);

    test.tick()?;
    test.assert_outgoing_eq(&[]);

    test.incoming(TcpPacket::new(1808, 80, 4001, 1 + 1 * 1024, 0, Vec::new()))?;
    test.assert_outgoing_eq(&[]);
    test.tick()?;
    test.assert_outgoing_eq(&[]);

    // Buffer is free once more
    // -> no direct ack, since no data was send
    // -> new send packet on tick
    test.incoming(TcpPacket::new(
        1808,
        80,
        4001,
        1 + 1 * 1024,
        1024,
        Vec::new(),
    ))?;
    test.assert_outgoing_eq(&[]);
    test.tick()?;
    test.assert_outgoing_eq(&[TcpPacket::new(
        80,
        1808,
        1 + 1024,
        4001,
        1024,
        data[1024..2048].to_vec(),
    )]);

    // Direct ack + window clear
    // -> no ACK but Datat
    test.incoming(TcpPacket::new(
        1808,
        80,
        4001,
        1 + 2 * 1024,
        1024,
        Vec::new(),
    ))?;
    test.assert_outgoing_eq(&[]);
    test.tick()?;
    test.assert_outgoing_eq(&[TcpPacket::new(
        80,
        1808,
        1 + 2 * 1024,
        4001,
        1024,
        data[2048..3072].to_vec(),
    )]);

    // Direct ack + window clear
    // -> no ACK but Datat
    test.incoming(TcpPacket::new(
        1808,
        80,
        4001,
        1 + 3 * 1024,
        1024,
        Vec::new(),
    ))?;
    test.assert_outgoing_eq(&[]);
    test.tick()?;
    test.assert_outgoing_eq(&[TcpPacket::new(
        80,
        1808,
        1 + 3 * 1024,
        4001,
        1024,
        data[3072..].to_vec(),
    )]);

    // no more data after final bytes
    test.incoming(TcpPacket::new(
        1808,
        80,
        4001,
        1 + 4 * 1024,
        1024,
        Vec::new(),
    ))?;
    test.assert_outgoing_eq(&[]);
    test.tick()?;
    test.assert_outgoing_eq(&[]);

    Ok(())
}

#[test]
fn tx_can_emit_multiple_packets() -> io::Result<()> {
    let mut test = TcpTestUnit::new(
        SocketAddr::new(Ipv4Addr::new(10, 0, 1, 104).into(), 80),
        SocketAddr::new(Ipv4Addr::new(20, 0, 2, 204).into(), 1808),
    );
    test.cfg(Config {
        send_buffer_cap: 4 * 1024,
        recv_buffer_cap: 4 * 1024,
        mss: Some(1400),
        ..Default::default()
    });

    test.handshake(4000, 3000)?;

    let data: Vec<u8> = (0..).map(|v| (v % 256) as u8).take(4 * 1024).collect();
    assert_eq!(4096, test.write(&data)?);

    test.tick()?;
    test.assert_outgoing_eq(&[
        TcpPacket::new(80, 1808, 1, 4001, WIN_4KB, data[..1400].to_vec()),
        TcpPacket::new(80, 1808, 1 + 1400, 4001, WIN_4KB, data[1400..2800].to_vec()),
        TcpPacket::new(
            80,
            1808,
            1 + 2 * 1400,
            4001,
            WIN_4KB,
            data[2800..3000].to_vec(),
        ),
    ]);

    test.tick()?;
    test.assert_outgoing_eq(&[]);

    test.incoming(TcpPacket::new(
        1808,
        80,
        4001,
        3001,
        WIN_4KB - 3000,
        Vec::new(),
    ))?;
    test.tick()?;
    test.assert_outgoing_eq(&[TcpPacket::new(
        80,
        1808,
        3001,
        4001,
        WIN_4KB,
        data[3000..].to_vec(),
    )]);

    Ok(())
}

#[test]
fn pcap_test_case() -> io::Result<()> {
    let client_addr = Ipv4Addr::new(10, 0, 1, 104);
    let server_addr = Ipv4Addr::new(20, 0, 2, 204);

    let mut client = TcpTestUnit::new(
        SocketAddr::new(client_addr.into(), 80),   // local
        SocketAddr::new(server_addr.into(), 1808), // peer
    );
    let mut server = TcpTestUnit::new(
        SocketAddr::new(server_addr.into(), 1808), // local
        SocketAddr::new(client_addr.into(), 80),   // peer
    );

    client.cfg.send_buffer_cap = 20_000;
    server.cfg.send_buffer_cap = 20_000;
    client.cfg.iss = Some(2000);
    server.cfg.iss = Some(8000);

    let mut writer = TestBlockWriter::new(
        Cursor::new(include_bytes!("captures/client.pcapng").as_slice()),
        "client",
    )?;
    writer.add_interface(
        &IfId::new("eth0"),
        Linktype::ETHERNET,
        4096,
        vec![
            InterfaceDescriptionOption::InterfaceName("Ethernet 0".to_string()),
            InterfaceDescriptionOption::InterfaceDescription("MSS 1500 SNAP 4096".to_string()),
        ],
    )?;

    client.connect()?;
    client.pipe_and_observe(&mut server, 1, |pkt| {
        capture_pkt(&mut writer, client_addr, server_addr, &pkt)
    })?;

    server.pipe_and_observe(&mut client, 1, |pkt| {
        capture_pkt(&mut writer, server_addr, client_addr, &pkt)
    })?;

    client.pipe_and_observe(&mut server, 1, |pkt| {
        capture_pkt(&mut writer, client_addr, server_addr, &pkt)
    })?;

    let n = client.write(&vec![42; 20_000])?;
    assert_eq!(n, 20_000);

    client.tick()?;
    client.pipe_and_observe(&mut server, 99, |pkt| {
        capture_pkt(&mut writer, client_addr, server_addr, &pkt)
    })?;

    server.pipe_and_observe(&mut client, 99, |pkt| {
        capture_pkt(&mut writer, server_addr, client_addr, &pkt)
    })?;

    Ok(())
}

fn capture_pkt<B: BlockWriter<IfId>>(
    w: &mut B,
    src: Ipv4Addr,
    dst: Ipv4Addr,
    pkt: &TcpPacket,
) -> io::Result<()> {
    let ip_packet = Ipv4Packet {
        dscp: 0,
        enc: 0,
        identification: 0,
        flags: Ipv4Flags {
            df: false,
            mf: false,
        },
        fragment_offset: 0,
        ttl: 64,
        proto: PROTO_TCP,
        src,
        dst,
        content: pkt.to_vec()?,
    };

    w.add_packet(
        &IfId::new("eth0"),
        0,
        ip_to_eth(src),
        ip_to_eth(dst),
        KIND_IPV4,
        &ip_packet,
        None,
    )
}

fn ip_to_eth(ip: Ipv4Addr) -> [u8; 6] {
    let mut buf = [1; 6];
    buf[2..].copy_from_slice(&ip.octets());
    buf
}
