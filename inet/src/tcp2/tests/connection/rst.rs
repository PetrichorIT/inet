use std::{
    io::{self, ErrorKind},
    net::{Ipv4Addr, SocketAddr},
};

use types::tcp::{TcpFlags, TcpPacket};

use crate::tcp2::{
    tests::connection::{TcpTestUnit, WIN_4KB},
    State,
};

// TODO: RST on listener state

#[test]
fn syn_snt_rst_on_invalid_ack() -> io::Result<()> {
    let mut test = TcpTestUnit::new(
        SocketAddr::new(Ipv4Addr::new(10, 0, 1, 104).into(), 80), // local
        SocketAddr::new(Ipv4Addr::new(20, 0, 2, 204).into(), 1808), // peer
    );

    test.connect()?;
    test.assert_outgoing_eq(&[TcpPacket::syn(80, 1808, 0, WIN_4KB)]);

    let mut invalid_syn_ack = TcpPacket::syn_ack(&TcpPacket::syn(80, 1808, 0, WIN_4KB), 1, WIN_4KB);
    invalid_syn_ack.ack_no = 0;

    test.incoming(invalid_syn_ack.clone())?;
    test.assert_outgoing_eq(&[TcpPacket::rst(0, WIN_4KB, &invalid_syn_ack)]);

    assert_eq!(test.state, State::SynSent);
    assert!(test.error.is_none());

    Ok(())
}

#[test]
fn syn_snt_incoming_rst_without_ack() -> io::Result<()> {
    let mut test = TcpTestUnit::new(
        SocketAddr::new(Ipv4Addr::new(10, 0, 1, 104).into(), 80), // local
        SocketAddr::new(Ipv4Addr::new(20, 0, 2, 204).into(), 1808), // peer
    );

    test.connect()?;
    test.assert_outgoing_eq(&[TcpPacket::syn(80, 1808, 0, WIN_4KB)]);

    let mut rst = TcpPacket::rst_for_syn(&TcpPacket::syn(80, 1808, 0, WIN_4KB));
    rst.flags = TcpFlags::RST;
    test.incoming(rst)?;
    test.assert_outgoing_eq(&[]);

    assert_eq!(test.state, State::SynSent);
    assert!(test.error.is_none());

    Ok(())
}

#[test]
fn syn_snt_incoming_rst_with_ack_refuse_connection() -> io::Result<()> {
    let mut test = TcpTestUnit::new(
        SocketAddr::new(Ipv4Addr::new(10, 0, 1, 104).into(), 80), // local
        SocketAddr::new(Ipv4Addr::new(20, 0, 2, 204).into(), 1808), // peer
    );

    test.connect()?;
    test.assert_outgoing_eq(&[TcpPacket::syn(80, 1808, 0, WIN_4KB)]);

    let rst = TcpPacket::rst_for_syn(&TcpPacket::syn(80, 1808, 0, WIN_4KB));
    test.incoming(rst)?;
    test.assert_outgoing_eq(&[]);

    assert_eq!(
        test.error.as_ref().map(|e| e.kind()),
        Some(ErrorKind::ConnectionReset)
    );
    assert_eq!(test.state, State::Closed);

    Ok(())
}

#[test]
fn segment_not_okay_full_window_empty_pkt() -> io::Result<()> {
    let mut test = TcpTestUnit::new(
        SocketAddr::new(Ipv4Addr::new(10, 0, 1, 104).into(), 80), // local
        SocketAddr::new(Ipv4Addr::new(20, 0, 2, 204).into(), 1808), // peer
    );
    test.cfg.mss = Some(WIN_4KB);
    test.handshake(4000, WIN_4KB)?;

    test.incoming(TcpPacket::new(
        1808,
        80,
        4001,
        1,
        WIN_4KB,
        vec![42; WIN_4KB as usize],
    ))?;
    test.clear_outgoing();
    assert_eq!(test.recv_window(), 0);

    let valid_segment = TcpPacket::new(1808, 80, test.rcv.nxt, 1, WIN_4KB, vec![]);
    let invalid_segment = TcpPacket::new(1808, 80, test.rcv.nxt + 1, 1, WIN_4KB, vec![]);

    test.incoming(valid_segment)?;
    test.assert_outgoing_eq(&[]);
    assert!(test.error.is_none());

    test.incoming(invalid_segment)?;
    test.assert_outgoing_eq(&[TcpPacket::new(
        80,
        1808,
        1,
        4001 + WIN_4KB as u32,
        0,
        Vec::new(),
    )]);

    Ok(())
}

#[test]
fn segment_not_okay_full_window_non_empty_pkt() -> io::Result<()> {
    let mut test = TcpTestUnit::new(
        SocketAddr::new(Ipv4Addr::new(10, 0, 1, 104).into(), 80), // local
        SocketAddr::new(Ipv4Addr::new(20, 0, 2, 204).into(), 1808), // peer
    );
    test.cfg.mss = Some(WIN_4KB);
    test.handshake(4000, WIN_4KB)?;

    test.incoming(TcpPacket::new(
        1808,
        80,
        4001,
        1,
        WIN_4KB,
        vec![42; WIN_4KB as usize],
    ))?;
    test.clear_outgoing();
    assert_eq!(test.recv_window(), 0);

    // there is no valid segment
    let invalid_segment = TcpPacket::new(1808, 80, test.rcv.nxt, 1, WIN_4KB, vec![1, 2, 3]);

    test.incoming(invalid_segment)?;
    test.assert_outgoing_eq(&[TcpPacket::new(
        80,
        1808,
        1,
        4001 + WIN_4KB as u32,
        0,
        Vec::new(),
    )]);

    Ok(())
}

#[test]
fn segment_not_okay_remaining_window_empty_pkt() -> io::Result<()> {
    let mut test = TcpTestUnit::new(
        SocketAddr::new(Ipv4Addr::new(10, 0, 1, 104).into(), 80), // local
        SocketAddr::new(Ipv4Addr::new(20, 0, 2, 204).into(), 1808), // peer
    );
    test.cfg.mss = Some(WIN_4KB);
    test.handshake(4000, WIN_4KB)?;

    // leaf a remaining window if 100
    test.incoming(TcpPacket::new(
        1808,
        80,
        4001,
        1,
        WIN_4KB,
        vec![42; (WIN_4KB - 100) as usize],
    ))?;
    test.clear_outgoing();
    assert_eq!(test.recv_window(), 100);

    let valid_segment = TcpPacket::new(1808, 80, test.rcv.nxt, 1, WIN_4KB, Vec::new());
    let invalid_segment = TcpPacket::new(1808, 80, test.rcv.nxt + 104, 1, WIN_4KB, Vec::new());

    test.incoming(valid_segment)?;
    test.assert_outgoing_eq(&[]);
    assert!(test.error.is_none());

    test.incoming(invalid_segment)?;
    test.assert_outgoing_eq(&[TcpPacket::new(
        80,
        1808,
        1,
        4001 + WIN_4KB as u32 - 100,
        100,
        Vec::new(),
    )]);

    Ok(())
}

#[test]
fn segment_not_okay_remaining_window_non_empty_pkt() -> io::Result<()> {
    let mut test = TcpTestUnit::new(
        SocketAddr::new(Ipv4Addr::new(10, 0, 1, 104).into(), 80), // local
        SocketAddr::new(Ipv4Addr::new(20, 0, 2, 204).into(), 1808), // peer
    );
    test.cfg.mss = Some(WIN_4KB);
    test.handshake(4000, WIN_4KB)?;

    // leaf a remaining window if 100
    test.incoming(TcpPacket::new(
        1808,
        80,
        4001,
        1,
        WIN_4KB,
        vec![42; (WIN_4KB - 100) as usize],
    ))?;
    test.clear_outgoing();
    assert_eq!(test.recv_window(), 100);

    // Condition
    // RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND or RCV.NXT =< SEG.SEQ+SEG.LEN-1 < RCV.NXT+RCV.WND
    // so: SEG.SEQ < RCV.NXT && SEG+LEN-1 < RCV.NXT
    // or: SEG.SEQ >= RCV.NXT+WND && SEG+LEN-1 > RCV.NXT+WND
    // theoretically combined with pkt, staring before the window, ending after the window

    let invalid_segment_a =
        TcpPacket::new(1808, 80, test.rcv.nxt - 130, 1, WIN_4KB, vec![120; 120]);
    let invalid_segment_b = TcpPacket::new(
        1808,
        80,
        test.rcv.nxt + test.recv_window() as u32,
        1,
        WIN_4KB,
        vec![120; 120],
    );
    let invalid_segment_c = TcpPacket::new(1808, 80, test.rcv.nxt - 130, 1, WIN_4KB, vec![5; 500]);

    test.incoming(invalid_segment_a)?;
    test.assert_outgoing_eq(&[TcpPacket::new(
        80,
        1808,
        1,
        4001 + WIN_4KB as u32 - 100,
        100,
        Vec::new(),
    )]);

    test.incoming(invalid_segment_b)?;
    test.assert_outgoing_eq(&[TcpPacket::new(
        80,
        1808,
        1,
        4001 + WIN_4KB as u32 - 100,
        100,
        Vec::new(),
    )]);

    // TODO:
    // This should probably not happen, since the packet contains good data, but both ends are bad.
    // However, sending such a packet, indicates lack of knowledge about the current window, so
    // dropping it might be a good idea
    test.incoming(invalid_segment_c)?;
    test.assert_outgoing_eq(&[TcpPacket::new(
        80,
        1808,
        1,
        4001 + WIN_4KB as u32 - 100,
        100,
        Vec::new(),
    )]);

    Ok(())
}

#[test]
fn ignore_rst_outside_current_window() -> io::Result<()> {
    let mut test = TcpTestUnit::new(
        SocketAddr::new(Ipv4Addr::new(10, 0, 1, 104).into(), 80), // local
        SocketAddr::new(Ipv4Addr::new(20, 0, 2, 204).into(), 1808), // peer
    );
    test.handshake(4000, WIN_4KB)?;

    // SEG.SEQ << WINDOW
    test.incoming(TcpPacket::rst(
        4000,
        WIN_4KB,
        &TcpPacket::new(80, 1808, 1, 4001, WIN_4KB, Vec::new()),
    ))?;
    test.assert_outgoing_eq(&[]);
    assert_eq!(test.incoming.pkts, []);

    // SEG.SEQ >> WINDOW
    test.incoming(TcpPacket::rst(
        14_000,
        WIN_4KB,
        &TcpPacket::new(80, 1808, 1, 4001, WIN_4KB, Vec::new()),
    ))?;
    test.assert_outgoing_eq(&[]);
    assert_eq!(test.incoming.pkts, []);

    Ok(())
}

#[test]
fn ack_rst_not_matching_seq_no() -> io::Result<()> {
    let mut test = TcpTestUnit::new(
        SocketAddr::new(Ipv4Addr::new(10, 0, 1, 104).into(), 80), // local
        SocketAddr::new(Ipv4Addr::new(20, 0, 2, 204).into(), 1808), // peer
    );
    test.handshake(4000, WIN_4KB)?;

    // Challenge ACK
    test.incoming(TcpPacket::rst(
        test.rcv.nxt + 1,
        WIN_4KB,
        &TcpPacket::new(80, 1808, 1, 4001, WIN_4KB, Vec::new()),
    ))?;
    test.assert_outgoing_eq(&[TcpPacket::new(80, 1808, 1, 4001, WIN_4KB, Vec::new())]);

    Ok(())
}

#[test]
fn valid_rst_in_syn_rcvd_simultaneous_open() -> io::Result<()> {
    let mut test = TcpTestUnit::new(
        SocketAddr::new(Ipv4Addr::new(10, 0, 1, 104).into(), 80), // local
        SocketAddr::new(Ipv4Addr::new(20, 0, 2, 204).into(), 1808), // peer
    );

    test.connect()?;
    test.assert_outgoing_eq(&[TcpPacket::syn(80, 1808, 0, WIN_4KB)]);

    let syn = TcpPacket::syn(1808, 80, 4000, WIN_4KB);
    test.incoming(syn)?;
    assert_eq!(test.state, State::SynRcvd);

    let rst = TcpPacket::rst(4001, WIN_4KB, &TcpPacket::syn(80, 1808, 0, WIN_4KB));
    test.incoming(rst)?;
    assert_eq!(test.state, State::Closed);
    assert_eq!(
        test.error.as_ref().map(|e| e.kind()),
        Some(ErrorKind::ConnectionRefused)
    );

    Ok(())
}

#[test]
fn valid_rst_in_syn_rcvd_passive_open() -> io::Result<()> {
    let mut test = TcpTestUnit::new(
        SocketAddr::new(Ipv4Addr::new(10, 0, 1, 104).into(), 80), // local
        SocketAddr::new(Ipv4Addr::new(20, 0, 2, 204).into(), 1808), // peer
    );

    let syn = TcpPacket::syn(1808, 80, 4000, WIN_4KB);
    test.incoming(syn.clone())?;

    let syn_ack = TcpPacket::syn_ack(&syn, 0, WIN_4KB);
    test.assert_outgoing_eq(&[syn_ack.clone()]);
    assert_eq!(test.state, State::SynRcvd);

    let rst_syn_ack = TcpPacket::rst(4001, WIN_4KB, &syn_ack);
    test.incoming(rst_syn_ack)?;
    assert_eq!(test.state, State::Closed);
    assert_eq!(
        test.error.as_ref().map(|e| e.kind()),
        Some(ErrorKind::ConnectionRefused)
    );

    Ok(())
}

#[test]
fn valid_rst_in_estab() -> io::Result<()> {
    let mut test = TcpTestUnit::new(
        SocketAddr::new(Ipv4Addr::new(10, 0, 1, 104).into(), 80), // local
        SocketAddr::new(Ipv4Addr::new(20, 0, 2, 204).into(), 1808), // peer
    );
    test.handshake(4000, WIN_4KB)?;

    test.incoming(TcpPacket::rst(
        4001,
        WIN_4KB,
        &TcpPacket::new(80, 1808, 1, 4001, WIN_4KB, Vec::new()),
    ))?;
    test.assert_outgoing_eq(&[]);
    assert_eq!(test.state, State::Closed);
    assert_eq!(
        test.error.as_ref().map(|e| e.kind()),
        Some(ErrorKind::ConnectionReset)
    );

    Ok(())
}

#[test]
fn valid_rst_in_closing_state_no_error() -> io::Result<()> {
    let mut test = TcpTestUnit::new(
        SocketAddr::new(Ipv4Addr::new(10, 0, 1, 104).into(), 80), // local
        SocketAddr::new(Ipv4Addr::new(20, 0, 2, 204).into(), 1808), // peer
    );
    test.handshake(4000, WIN_4KB)?;

    // FIN
    test.close()?;
    test.tick()?;
    test.assert_outgoing_eq(&[TcpPacket::new(80, 1808, 1, 4001, WIN_4KB, Vec::new()).fin(true)]);

    // Remote FIN not yet ACK of FIN
    test.incoming(TcpPacket::new(1808, 80, 4001, 1, WIN_4KB, Vec::new()).fin(true))?;
    assert_eq!(test.state, State::Closing);

    test.incoming(TcpPacket::rst(
        4002,
        WIN_4KB,
        &TcpPacket::new(80, 1808, 2, 4002, WIN_4KB, Vec::new()),
    ))?;
    assert_eq!(test.state, State::Closed);
    assert!(test.error.is_none());

    Ok(())
}

#[test]
fn valid_rst_in_time_wait_state_no_error() -> io::Result<()> {
    let mut test = TcpTestUnit::new(
        SocketAddr::new(Ipv4Addr::new(10, 0, 1, 104).into(), 80), // local
        SocketAddr::new(Ipv4Addr::new(20, 0, 2, 204).into(), 1808), // peer
    );
    test.handshake(4000, WIN_4KB)?;

    // FIN
    test.close()?;
    test.tick()?;
    test.assert_outgoing_eq(&[TcpPacket::new(80, 1808, 1, 4001, WIN_4KB, Vec::new()).fin(true)]);

    // Remote FIN not yet ACK of FIN
    test.incoming(TcpPacket::new(1808, 80, 4001, 2, WIN_4KB, Vec::new()))?;
    test.incoming(TcpPacket::new(1808, 80, 4001, 2, WIN_4KB, Vec::new()).fin(true))?;
    assert_eq!(test.state, State::TimeWait);

    test.incoming(TcpPacket::rst(
        4002,
        WIN_4KB,
        &TcpPacket::new(80, 1808, 2, 4002, WIN_4KB, Vec::new()),
    ))?;
    assert_eq!(test.state, State::Closed);
    assert!(test.error.is_none());

    Ok(())
}

#[test]
fn valid_rst_in_last_ack_state_no_error() -> io::Result<()> {
    let mut test = TcpTestUnit::new(
        SocketAddr::new(Ipv4Addr::new(10, 0, 1, 104).into(), 80), // local
        SocketAddr::new(Ipv4Addr::new(20, 0, 2, 204).into(), 1808), // peer
    );
    test.handshake(4000, WIN_4KB)?;

    // Remote FIN
    test.incoming(TcpPacket::new(1808, 80, 4001, 1, WIN_4KB, Vec::new()).fin(true))?;
    test.assert_outgoing_eq(&[TcpPacket::new(80, 1808, 1, 4002, WIN_4KB, Vec::new())]);

    test.close()?;
    test.tick()?;
    test.assert_outgoing_eq(&[TcpPacket::new(80, 1808, 1, 4002, WIN_4KB, Vec::new()).fin(true)]);
    assert_eq!(test.state, State::LastAck);

    test.incoming(TcpPacket::rst(
        4002,
        WIN_4KB,
        &TcpPacket::new(80, 1808, 1, 4002, WIN_4KB, Vec::new()),
    ))?;
    assert_eq!(test.state, State::Closed);
    assert!(test.error.is_none());

    Ok(())
}
