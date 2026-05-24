use std::{
    io,
    net::{Ipv4Addr, SocketAddr},
};

use types::tcp::TcpPacket;

use crate::tcp::tests::connection::{TcpTestUnit, WIN_4KB};

#[test]
fn no_delay() -> io::Result<()> {
    let mut test = TcpTestUnit::new(
        SocketAddr::new(Ipv4Addr::new(10, 0, 1, 104).into(), 80), // local
        SocketAddr::new(Ipv4Addr::new(20, 0, 2, 204).into(), 1808), // peer
    );
    test.handshake(4000, WIN_4KB)?;

    test.write(&[1])?;
    test.on_tick()?;
    test.assert_outgoing_eq(&[TcpPacket::new(80, 1808, 1, 4001, WIN_4KB, vec![1]).psh()]);

    test.write(&[8; 800])?;
    test.on_tick()?;
    test.assert_outgoing_eq(&[
        TcpPacket::new(80, 1808, 2, 4001, WIN_4KB, vec![8; 536]),
        TcpPacket::new(80, 1808, 538, 4001, WIN_4KB, vec![8; 264]).psh(),
    ]);

    Ok(())
}

#[test]
fn with_delay_continue_after_empty_pipe() -> io::Result<()> {
    // des::tracing::init();

    let mut test = TcpTestUnit::new(
        SocketAddr::new(Ipv4Addr::new(10, 0, 1, 104).into(), 80), // local
        SocketAddr::new(Ipv4Addr::new(20, 0, 2, 204).into(), 1808), // peer
    );
    test.cfg.no_delay = false;
    test.handshake(4000, WIN_4KB)?;

    // Force one small packet to be in-flight to cirumvent nagle-mod
    test.write(&[1])?;
    test.on_tick()?;
    test.assert_outgoing_eq(&[TcpPacket::new(80, 1808, 1, 4001, WIN_4KB, vec![1]).psh()]);

    test.write(&[8; 800])?;
    test.on_tick()?;
    test.assert_outgoing_eq(&[
        TcpPacket::new(80, 1808, 2, 4001, WIN_4KB, vec![8; 536]),
        // Remaining 264 bytes are suppressed until either full MSS or pipe empty of small segments
    ]);

    // <- ACK (pipe empty of small segments)
    test.incoming(TcpPacket::new(1808, 80, 4001, 2, WIN_4KB, vec![]))?;
    test.on_tick()?;
    test.assert_outgoing_eq(&[TcpPacket::new(80, 1808, 538, 4001, WIN_4KB, vec![8; 264]).psh()]);

    Ok(())
}

#[test]
fn with_delay_continue_after_full_mss() -> io::Result<()> {
    let mut test = TcpTestUnit::new(
        SocketAddr::new(Ipv4Addr::new(10, 0, 1, 104).into(), 80), // local
        SocketAddr::new(Ipv4Addr::new(20, 0, 2, 204).into(), 1808), // peer
    );
    test.cfg.no_delay = false;
    test.handshake(4000, WIN_4KB)?;

    // Force one small packet to be in-flight to cirumvent nagle-mod
    test.write(&[1])?;
    test.on_tick()?;
    test.assert_outgoing_eq(&[TcpPacket::new(80, 1808, 1, 4001, WIN_4KB, vec![1]).psh()]);

    test.write(&[8; 800])?;
    test.on_tick()?;
    test.assert_outgoing_eq(&[
        TcpPacket::new(80, 1808, 2, 4001, WIN_4KB, vec![8; 536]),
        // Remaining 264 bytes are suppressed until either full MSS or pipe empty
    ]);

    // more data
    test.write(&[8; 536 - 264])?;
    test.on_tick()?;
    test.assert_outgoing_eq(&[TcpPacket::new(80, 1808, 538, 4001, WIN_4KB, vec![8; 536]).psh()]);

    Ok(())
}

#[test]
fn with_delay_allow_one_small_segment() -> io::Result<()> {
    let mut test = TcpTestUnit::new(
        SocketAddr::new(Ipv4Addr::new(10, 0, 1, 104).into(), 80), // local
        SocketAddr::new(Ipv4Addr::new(20, 0, 2, 204).into(), 1808), // peer
    );
    test.cfg.no_delay = false;
    test.handshake(4000, WIN_4KB)?;

    // One is allowed
    test.write(&[8; 800])?;
    test.on_tick()?;
    test.assert_outgoing_eq(&[
        TcpPacket::new(80, 1808, 1, 4001, WIN_4KB, vec![8; 536]),
        TcpPacket::new(80, 1808, 537, 4001, WIN_4KB, vec![8; 264]).psh(),
    ]);

    // More are not
    test.write(&[8; 800])?;
    test.on_tick()?;
    test.assert_outgoing_eq(&[TcpPacket::new(80, 1808, 801, 4001, WIN_4KB, vec![8; 536])]);

    Ok(())
}

#[test]
fn with_delay_prevent_small_packets() -> io::Result<()> {
    let mut test = TcpTestUnit::new(
        SocketAddr::new(Ipv4Addr::new(10, 0, 1, 104).into(), 80), // local
        SocketAddr::new(Ipv4Addr::new(20, 0, 2, 204).into(), 1808), // peer
    );
    test.cfg.no_delay = false;
    test.handshake(4000, WIN_4KB)?;

    let mut pkts = Vec::new();
    for _ in 0..1000 {
        test.write(&[1])?;
        test.on_tick()?;
        test.assert_outgoing(|mut pkt| pkts.append(&mut pkt));
    }

    assert_eq!(
        pkts,
        &[
            TcpPacket::new(80, 1808, 1, 4001, WIN_4KB, vec![1]).psh(),
            TcpPacket::new(80, 1808, 2, 4001, WIN_4KB, vec![1; 536]).psh(),
        ]
    );

    Ok(())
}
