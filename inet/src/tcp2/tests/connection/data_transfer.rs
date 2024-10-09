use crate::tcp2::{
    tests::connection::{TcpTestUnit, WIN_4KB},
    Config,
};
use std::{
    io,
    net::{Ipv4Addr, SocketAddr},
};
use types::tcp::TcpPacket;

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
