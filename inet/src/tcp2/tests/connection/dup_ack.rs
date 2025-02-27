use std::{
    io,
    net::{Ipv4Addr, SocketAddr},
};

use types::tcp::TcpPacket;

use super::{TcpTestUnit, WIN_4KB};

#[test]
fn dup_ack_send_on_out_of_order_packet() -> io::Result<()> {
    let mut test = TcpTestUnit::new(
        SocketAddr::new(Ipv4Addr::new(10, 0, 1, 104).into(), 80), // local
        SocketAddr::new(Ipv4Addr::new(20, 0, 2, 204).into(), 1808), // peer
    );

    test.handshake(4000, WIN_4KB)?;

    test.incoming(TcpPacket::new(1808, 80, 4001, 1, WIN_4KB, vec![42; 500]))?;
    test.assert_outgoing_eq(&[TcpPacket::new(80, 1808, 1, 4501, WIN_4KB - 500, Vec::new())]);

    test.incoming(TcpPacket::new(1808, 80, 5001, 1, WIN_4KB, vec![52; 500]))?;
    test.assert_outgoing_eq(&[TcpPacket::new(80, 1808, 1, 4501, WIN_4KB - 500, Vec::new())]);

    assert_eq!(test.incoming.pkts.len(), 1);

    Ok(())
}

#[test]
fn dup_ack_recognized() -> io::Result<()> {
    // des::tracing::init();

    let mut test = TcpTestUnit::new(
        SocketAddr::new(Ipv4Addr::new(10, 0, 1, 104).into(), 80), // local
        SocketAddr::new(Ipv4Addr::new(20, 0, 2, 204).into(), 1808), // peer
    );

    test.cfg.dup_ack_resend_cnt = Some(1);

    test.handshake(4000, WIN_4KB)?;
    test.snd.mss = 500;

    test.write(&vec![42; 1500])?;
    test.tick()?;
    test.clear_outgoing();

    test.incoming(TcpPacket::new(1808, 80, 4001, 501, WIN_4KB, Vec::new()))?;
    test.assert_outgoing_eq(&[]);

    test.incoming(TcpPacket::new(1808, 80, 4001, 501, WIN_4KB, Vec::new()))?;
    test.assert_outgoing_eq(&[TcpPacket::new(80, 1808, 501, 4001, WIN_4KB, vec![42; 500])]);

    Ok(())
}
