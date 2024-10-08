use types::tcp::TcpPacket;

use super::{TcpTestUnit, WIN_4KB};
use std::{
    io,
    iter::repeat,
    net::{Ipv4Addr, SocketAddr},
};

#[test]
fn slow_start_doubles_window() -> io::Result<()> {
    let mut test = TcpTestUnit::new(
        SocketAddr::new(Ipv4Addr::new(10, 0, 1, 104).into(), 80), // local
        SocketAddr::new(Ipv4Addr::new(20, 0, 2, 204).into(), 1808), // peer
    );
    test.cfg.enable_congestion_control = true;
    test.cfg.send_buffer_cap = u16::MAX as usize;

    test.handshake(4000, WIN_4KB)?;

    assert_eq!(test.cong.wnd, 536);

    let data: Vec<u8> = repeat(8).take(536 * 7).collect();
    assert_eq!(test.write(&data)?, 7 * 536);

    // First RT
    test.tick()?;
    test.assert_outgoing_eq(&[TcpPacket::new(80, 1808, 1, 4001, WIN_4KB, vec![8; 536])]);
    test.incoming(TcpPacket::new(
        1808,
        80,
        4001,
        1 + 536,
        WIN_4KB - 536,
        Vec::new(),
    ))?;

    assert_eq!(test.cong.wnd, 2 * 536);

    // Second RT
    test.tick()?;
    test.assert_outgoing_eq(&[
        TcpPacket::new(80, 1808, 1 + 536, 4001, WIN_4KB, vec![8; 536]),
        TcpPacket::new(80, 1808, 1 + 2 * 536, 4001, WIN_4KB, vec![8; 536]),
    ]);
    test.incoming(TcpPacket::new(
        1808,
        80,
        4001,
        1 + 3 * 536,
        WIN_4KB - 3 * 536,
        Vec::new(),
    ))?;

    assert_eq!(test.cong.wnd, 3 * 536);

    Ok(())
}

#[test]
fn congestion_avoidance_additive_increase() -> io::Result<()> {
    let mut test = TcpTestUnit::new(
        SocketAddr::new(Ipv4Addr::new(10, 0, 1, 104).into(), 80), // local
        SocketAddr::new(Ipv4Addr::new(20, 0, 2, 204).into(), 1808), // peer
    );
    test.cfg.enable_congestion_control = true;
    test.cfg.send_buffer_cap = u16::MAX as usize;

    test.handshake(4000, WIN_4KB)?;

    // Slow start (+1 per ACK)
    test.write_and_ack(&[1])?;
    test.write_and_ack(&[2])?;
    test.write_and_ack(&[3])?;

    assert_eq!(test.cong.wnd, 4 * 536);

    // Congestion avoidance (count bytes ACKEed)
    test.write_and_ack(&vec![8; 536])?;

    assert_eq!(test.cong.avoid_counter, 3 * 536);
    assert_eq!(test.cong.wnd, 4 * 536);

    // Saturation over 0, AI
    test.write_and_ack(&vec![8; 3 * 536])?;
    assert_eq!(test.cong.wnd, 5 * 536);
    assert_eq!(test.cong.avoid_counter, 5 * 536);

    Ok(())
}

#[test]
fn congestion_avoidance_multiplicative_decrease() -> io::Result<()> {
    let mut test = TcpTestUnit::new(
        SocketAddr::new(Ipv4Addr::new(10, 0, 1, 104).into(), 80), // local
        SocketAddr::new(Ipv4Addr::new(20, 0, 2, 204).into(), 1808), // peer
    );
    test.cfg.enable_congestion_control = true;

    test.handshake(4000, WIN_4KB)?;

    // Slow start
    test.write_and_ack(&[1])?;
    test.write_and_ack(&[2])?;
    test.write_and_ack(&[3])?;

    assert_eq!(test.cong.wnd, 4 * 536);

    // <- DATA
    test.write(&[4])?;
    test.tick()?;
    test.clear_outgoing();

    // Lost '1 (multiplicative decrease)
    test.set_time(15.0);
    test.tick()?;
    test.assert_outgoing_eq(&[TcpPacket::new(80, 1808, 4, 4001, WIN_4KB, vec![4])]);
    assert_eq!(test.cong.wnd, 2 * 536);

    // Lost '2 (multiplicative decrease)
    test.set_time(30.0);
    test.tick()?;
    test.assert_outgoing_eq(&[TcpPacket::new(80, 1808, 4, 4001, WIN_4KB, vec![4])]);
    assert_eq!(test.cong.wnd, 536);

    // Lost '3 (lower bound of 1 MSS)
    test.set_time(45.0);
    test.tick()?;
    test.assert_outgoing_eq(&[TcpPacket::new(80, 1808, 4, 4001, WIN_4KB, vec![4])]);
    assert_eq!(test.cong.wnd, 536);

    Ok(())
}
