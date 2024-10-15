use std::{
    io,
    net::{Ipv4Addr, SocketAddr},
};

use types::tcp::TcpPacket;

use super::{TcpTestUnit, WIN_4KB};

#[test]
fn window_updates_prefer_higher_seqno() -> io::Result<()> {
    let mut test = TcpTestUnit::new(
        SocketAddr::new(Ipv4Addr::new(10, 0, 1, 104).into(), 80),
        SocketAddr::new(Ipv4Addr::new(20, 0, 2, 204).into(), 1808),
    );

    test.handshake(4000, WIN_4KB)?;

    // Send two data packets, expecting two acks
    test.write(&[1; 800])?;
    test.tick()?;
    test.assert_outgoing_eq(&[
        TcpPacket::new(80, 1808, 1, 4001, WIN_4KB, vec![1; 536]),
        TcpPacket::new(80, 1808, 537, 4001, WIN_4KB, vec![1; 800 - 536]),
    ]);

    let ack1 = TcpPacket::new(1808, 80, 4001, 537, WIN_4KB - 536, Vec::new());
    let ack2 = TcpPacket::new(1808, 80, 4001, 801, WIN_4KB - 800, Vec::new());

    test.incoming(ack2)?;
    assert_eq!(test.num_unacked_bytes(), 0);
    assert_eq!(test.snd.wnd, WIN_4KB - 800);

    test.incoming(ack1)?;
    assert_eq!(test.num_unacked_bytes(), 0);
    assert_eq!(test.snd.wnd, WIN_4KB - 800);

    Ok(())
}

#[test]
fn data_pakets_out_of_order() -> io::Result<()> {
    let mut test = TcpTestUnit::new(
        SocketAddr::new(Ipv4Addr::new(10, 0, 1, 104).into(), 80),
        SocketAddr::new(Ipv4Addr::new(20, 0, 2, 204).into(), 1808),
    );

    test.handshake(4000, WIN_4KB)?;

    // Send two data packets
    // ISS is 4000 DSN is 4001
    let data1 = TcpPacket::new(1808, 80, 4001, 1, WIN_4KB, vec![1; 536]);
    let data2 = TcpPacket::new(1808, 80, 4537, 1, WIN_4KB, vec![1; 800 - 536]);

    test.incoming(data2)?;
    assert_eq!(test.received, []);

    test.incoming(data1)?;
    assert_eq!(test.received, vec![1; 800]);

    Ok(())
}

#[test]
fn data_pakets_ignores_invalid_packets() -> io::Result<()> {
    let mut test = TcpTestUnit::new(
        SocketAddr::new(Ipv4Addr::new(10, 0, 1, 104).into(), 80),
        SocketAddr::new(Ipv4Addr::new(20, 0, 2, 204).into(), 1808),
    );

    test.handshake(4000, WIN_4KB)?;

    // Send invalid data acket
    let data1 = TcpPacket::new(1808, 80, 4001, 1, WIN_4KB, vec![1; 536]);
    let data_out_of_bounds = TcpPacket::new(1808, 80, 123537, 1, WIN_4KB, vec![1; 800 - 536]);

    test.incoming(data_out_of_bounds)?;
    assert_eq!(test.received, []);
    assert_eq!(test.incoming.pkts, []);

    test.incoming(data1)?;
    assert_eq!(test.received, vec![1; 536]);

    Ok(())
}
