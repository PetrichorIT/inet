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

#[test]
fn tx_flush() -> io::Result<()> {
    let mut test = TcpTestUnit::new(
        SocketAddr::new(Ipv4Addr::new(10, 0, 1, 104).into(), 80),
        SocketAddr::new(Ipv4Addr::new(20, 0, 2, 204).into(), 1808),
    );

    test.handshake(4000, 500)?;

    test.write(&vec![1; 750])?;
    assert_eq!(test.is_flushed(), false);

    test.tick()?;
    test.assert_outgoing_eq(&[TcpPacket::new(80, 1808, 1, 4001, WIN_4KB, vec![1; 500])]);
    assert_eq!(test.is_flushed(), false);

    test.incoming(TcpPacket::new(1808, 80, 4001, 501, 500, Vec::new()))?;
    test.tick()?;
    test.assert_outgoing_eq(&[TcpPacket::new(80, 1808, 501, 4001, WIN_4KB, vec![1; 250])]);
    assert_eq!(test.is_flushed(), false);

    test.incoming(TcpPacket::new(1808, 80, 4001, 751, 500, Vec::new()))?;
    assert_eq!(test.is_flushed(), true);

    Ok(())
}

#[test]
fn rcv_wnd_updates_at_read() -> io::Result<()> {
    let mut test = TcpTestUnit::new(
        SocketAddr::new(Ipv4Addr::new(10, 0, 1, 104).into(), 80),
        SocketAddr::new(Ipv4Addr::new(20, 0, 2, 204).into(), 1808),
    );
    test.cfg.recv_buffer_cap = 1024;

    test.handshake(4000, WIN_4KB)?;
    assert_eq!(test.rcv.wnd, 1024);

    test.incoming(TcpPacket::new(1808, 80, 4001, 1, WIN_4KB, vec![100; 100]))?;
    test.clear_outgoing();
    assert_eq!(test.rcv.wnd, 1024 - 100);

    let mut buf = [0; 100];
    let n = test.read(&mut buf)?;
    assert_eq!(n, 100);
    assert_eq!(test.rcv.wnd, 1024);

    Ok(())
}

#[test]
fn rcv_wnd_no_updates_at_peek() -> io::Result<()> {
    let mut test = TcpTestUnit::new(
        SocketAddr::new(Ipv4Addr::new(10, 0, 1, 104).into(), 80),
        SocketAddr::new(Ipv4Addr::new(20, 0, 2, 204).into(), 1808),
    );
    test.cfg.recv_buffer_cap = 1024;

    test.handshake(4000, WIN_4KB)?;
    assert_eq!(test.rcv.wnd, 1024);

    test.incoming(TcpPacket::new(1808, 80, 4001, 1, WIN_4KB, vec![100; 100]))?;
    test.clear_outgoing();
    assert_eq!(test.rcv.wnd, 1024 - 100);

    let mut buf = [0; 100];
    let n = test.peek(&mut buf)?;
    assert_eq!(n, 100);
    assert_eq!(test.rcv.wnd, 1024 - 100);

    Ok(())
}

#[test]
fn sender_lost_pkt_will_be_retransmitted() -> io::Result<()> {
    // des::tracing::init();

    let mut test = TcpTestUnit::new(
        SocketAddr::new(Ipv4Addr::new(10, 0, 1, 104).into(), 80),
        SocketAddr::new(Ipv4Addr::new(20, 0, 2, 204).into(), 1808),
    );

    test.handshake(4000, WIN_4KB)?;
    test.snd.mss = 500;

    test.write(&vec![42; 2000])?;
    test.tick()?;

    test.assert_outgoing_eq(&[
        TcpPacket::new(80, 1808, 1, 4001, WIN_4KB, vec![42; 500]),
        TcpPacket::new(80, 1808, 501, 4001, WIN_4KB, vec![42; 500]), // lost
        TcpPacket::new(80, 1808, 1001, 4001, WIN_4KB, vec![42; 500]),
        TcpPacket::new(80, 1808, 1501, 4001, WIN_4KB, vec![42; 500]),
    ]);

    test.incoming(TcpPacket::new(1808, 80, 4001, 501, WIN_4KB, Vec::new()))?;
    test.tick()?;
    test.assert_outgoing_eq(&[]);

    let next_to = test.next_timeout().expect("req timeout");
    test.set_time(next_to);

    test.tick()?;
    test.assert_outgoing_eq(&[
        TcpPacket::new(80, 1808, 501, 4001, WIN_4KB, vec![42; 500]), // prev. lost
        TcpPacket::new(80, 1808, 1001, 4001, WIN_4KB, vec![42; 500]),
        TcpPacket::new(80, 1808, 1501, 4001, WIN_4KB, vec![42; 500]),
    ]);

    test.set_time(test.next_timeout().expect("failed"));
    test.assert_outgoing_eq(&[]);

    test.incoming(TcpPacket::new(1808, 80, 4001, 1001, WIN_4KB, Vec::new()))?;
    test.incoming(TcpPacket::new(1808, 80, 4001, 1501, WIN_4KB, Vec::new()))?;
    test.incoming(TcpPacket::new(1808, 80, 4001, 2001, WIN_4KB, Vec::new()))?;

    test.tick()?;
    test.assert_outgoing_eq(&[]);
    assert_eq!(test.snd.num_unacked_bytes(), 0);

    Ok(())
}

#[test]
fn sender_multiple_same_seg_timeouts() -> io::Result<()> {
    let mut test = TcpTestUnit::new(
        SocketAddr::new(Ipv4Addr::new(10, 0, 1, 104).into(), 80),
        SocketAddr::new(Ipv4Addr::new(20, 0, 2, 204).into(), 1808),
    );

    test.handshake(4000, WIN_4KB)?;
    test.snd.mss = 500;

    test.write(&vec![42; 1000])?;
    test.tick()?;

    test.assert_outgoing_eq(&[
        TcpPacket::new(80, 1808, 1, 4001, WIN_4KB, vec![42; 500]), // lost
        TcpPacket::new(80, 1808, 501, 4001, WIN_4KB, vec![42; 500]),
    ]);

    for _ in 0..3 {
        let next_to = test.next_timeout().expect("req timeout");
        test.set_time(next_to);

        test.tick()?;
        test.assert_outgoing_eq(&[
            TcpPacket::new(80, 1808, 1, 4001, WIN_4KB, vec![42; 500]), // lost
            TcpPacket::new(80, 1808, 501, 4001, WIN_4KB, vec![42; 500]),
        ]);
    }

    assert_eq!(test.now(), 30.0);

    Ok(())
}

#[test]
fn sender_progresses_after_partial_retransmission_success() -> io::Result<()> {
    let mut test = TcpTestUnit::new(
        SocketAddr::new(Ipv4Addr::new(10, 0, 1, 104).into(), 80),
        SocketAddr::new(Ipv4Addr::new(20, 0, 2, 204).into(), 1808),
    );

    test.handshake(4000, WIN_4KB)?;
    test.snd.mss = 500;

    test.write(&vec![42; 1000])?;
    test.tick()?;

    test.assert_outgoing_eq(&[
        TcpPacket::new(80, 1808, 1, 4001, WIN_4KB, vec![42; 500]), // lost
        TcpPacket::new(80, 1808, 501, 4001, WIN_4KB, vec![42; 500]),
    ]);

    // Failed Transmission
    test.set_time(test.next_timeout().expect("req timeout"));

    test.tick()?;
    test.assert_outgoing_eq(&[
        TcpPacket::new(80, 1808, 1, 4001, WIN_4KB, vec![42; 500]), // lost
        TcpPacket::new(80, 1808, 501, 4001, WIN_4KB, vec![42; 500]),
    ]);

    // Partial Sucess
    test.incoming(TcpPacket::new(1808, 80, 4001, 501, WIN_4KB, Vec::new()))?;
    test.set_time(test.next_timeout().expect("req timeout"));

    test.tick()?;
    test.assert_outgoing_eq(&[TcpPacket::new(80, 1808, 501, 4001, WIN_4KB, vec![42; 500])]);

    Ok(())
}

#[test]
fn sender_progresses_beyond_window_after_retransmission() -> io::Result<()> {
    let mut test = TcpTestUnit::new(
        SocketAddr::new(Ipv4Addr::new(10, 0, 1, 104).into(), 80),
        SocketAddr::new(Ipv4Addr::new(20, 0, 2, 204).into(), 1808),
    );

    test.handshake(4000, 500)?;
    test.snd.mss = 500;

    test.write(&vec![42; 1000])?;
    test.tick()?;

    test.assert_outgoing_eq(&[TcpPacket::new(80, 1808, 1, 4001, WIN_4KB, vec![42; 500])]);

    // Failed Transmission
    test.set_time(test.next_timeout().expect("req timeout"));

    test.tick()?;
    test.assert_outgoing_eq(&[TcpPacket::new(80, 1808, 1, 4001, WIN_4KB, vec![42; 500])]);

    //  Sucess, Window progress
    test.incoming(TcpPacket::new(1808, 80, 4001, 501, WIN_4KB, Vec::new()))?;

    test.tick()?;
    test.assert_outgoing_eq(&[TcpPacket::new(80, 1808, 501, 4001, WIN_4KB, vec![42; 500])]);

    Ok(())
}

#[test]
fn receiver_can_use_reorder_buffer_at_retransmit() -> io::Result<()> {
    let mut test = TcpTestUnit::new(
        SocketAddr::new(Ipv4Addr::new(10, 0, 1, 104).into(), 80),
        SocketAddr::new(Ipv4Addr::new(20, 0, 2, 204).into(), 1808),
    );

    test.handshake(4000, WIN_4KB)?;

    // Packets
    // 1: seq4001
    // 2: seq4501 never received
    // 3: seq5001 reorder buffer

    test.incoming(TcpPacket::new(1808, 80, 4001, 1, WIN_4KB, vec![69; 500]))?;
    test.incoming(TcpPacket::new(1808, 80, 5001, 1, WIN_4KB, vec![69; 500]))?;

    assert_eq!(test.received.len(), 500);
    assert_eq!(test.incoming.pkts.len(), 1);

    test.incoming(TcpPacket::new(1808, 80, 4501, 1, WIN_4KB, vec![42; 500]))?;

    assert_eq!(test.received.len(), 1500);
    assert_eq!(test.incoming.pkts.len(), 0);

    Ok(())
}
