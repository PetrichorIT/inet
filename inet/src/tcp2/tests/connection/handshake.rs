use std::{
    io,
    net::{Ipv4Addr, SocketAddr},
};

use types::tcp::{TcpFlags, TcpPacket};

use crate::tcp2::{tests::connection::WIN_4KB, State};

use super::TcpTestUnit;

#[test]
fn normal() -> io::Result<()> {
    let mut test = TcpTestUnit::new(
        SocketAddr::new(Ipv4Addr::new(10, 0, 1, 104).into(), 80),
        SocketAddr::new(Ipv4Addr::new(20, 0, 2, 204).into(), 1808),
    );

    test.incoming(TcpPacket::syn(1808, 80, 4000, 1024))?;
    test.assert_connection_exists();

    let mut syn_ack = TcpPacket::syn(80, 1808, 0, WIN_4KB);
    syn_ack.flags.insert(TcpFlags::ACK);
    syn_ack.ack_no = 4001;
    test.assert_outgoing_eq(&[syn_ack]);

    test.incoming(TcpPacket::new(
        1808,
        80,
        4001,
        1,
        1024,
        vec![1, 2, 3, 4, 5, 5, 7, 8],
    ))?;
    test.assert_outgoing_eq(&[TcpPacket::new(80, 1808, 1, 4009, WIN_4KB - 8, Vec::new())]);

    Ok(())
}

#[test]
fn connect() -> io::Result<()> {
    let mut test = TcpTestUnit::new(
        SocketAddr::new(Ipv4Addr::new(10, 0, 1, 104).into(), 80), // local
        SocketAddr::new(Ipv4Addr::new(20, 0, 2, 204).into(), 1808), // peer
    );

    // -> SYN
    test.connect()?;
    test.assert_outgoing_eq(&[TcpPacket::syn(80, 1808, 0, WIN_4KB)]);

    // <- SYNACK
    // -> ACK
    let mut syn_ack = TcpPacket::syn(1808, 80, 4000, WIN_4KB);
    syn_ack.flags.insert(TcpFlags::ACK);
    syn_ack.ack_no = 1;
    test.incoming(syn_ack)?;
    test.assert_outgoing_eq(&[TcpPacket::new(80, 1808, 1, 4001, WIN_4KB, Vec::new())]);

    Ok(())
}

#[test]
fn connect_syn_timeout() -> io::Result<()> {
    let mut test = TcpTestUnit::new(
        SocketAddr::new(Ipv4Addr::new(10, 0, 1, 104).into(), 80), // local
        SocketAddr::new(Ipv4Addr::new(20, 0, 2, 204).into(), 1808), // peer
    );

    // -> SYN
    test.connect()?;
    test.assert_outgoing_eq(&[TcpPacket::syn(80, 1808, 0, WIN_4KB)]);
    assert_eq!(test.next_timeout(), Some(15.0.into()));

    test.tick()?;
    test.assert_outgoing_eq(&[]);

    test.set_time(15.0);
    test.tick()?;
    test.assert_outgoing_eq(&[TcpPacket::syn(80, 1808, 0, WIN_4KB)]);

    // <- SYNACK
    // -> ACK
    let mut syn_ack = TcpPacket::syn(1808, 80, 4000, WIN_4KB);
    syn_ack.flags.insert(TcpFlags::ACK);
    syn_ack.ack_no = 1;

    test.set_time(17.0);
    test.incoming(syn_ack)?;
    test.assert_outgoing_eq(&[TcpPacket::new(80, 1808, 1, 4001, WIN_4KB, Vec::new())]);

    Ok(())
}

#[test]
fn connect_closed_after_too_many_syn_timeouts() -> io::Result<()> {
    let mut test = TcpTestUnit::new(
        SocketAddr::new(Ipv4Addr::new(10, 0, 1, 104).into(), 80), // local
        SocketAddr::new(Ipv4Addr::new(20, 0, 2, 204).into(), 1808), // peer
    );

    // -> SYN (initial)
    test.connect()?;
    test.assert_outgoing_eq(&[TcpPacket::syn(80, 1808, 0, WIN_4KB)]);
    assert_eq!(test.next_timeout(), Some(15.0.into()));

    // repeats nr 1,2,3
    for t in [15.0, 30.0, 45.0] {
        test.set_time(t);
        test.tick()?;
        test.assert_outgoing_eq(&[TcpPacket::syn(80, 1808, 0, WIN_4KB)]);
        assert_eq!(test.state, State::SynSent);
    }

    // full timeout
    test.set_time(60.0);
    test.tick()?;
    test.assert_outgoing_eq(&[]);
    assert_eq!(test.state, State::Closed);

    Ok(())
}

#[test]
fn connect_regulated_mss() -> io::Result<()> {
    let mut test = TcpTestUnit::new(
        SocketAddr::new(Ipv4Addr::new(10, 0, 1, 104).into(), 80), // local
        SocketAddr::new(Ipv4Addr::new(20, 0, 2, 204).into(), 1808), // peer
    );

    test.connect()?;
    test.assert_outgoing_eq(&[TcpPacket::syn(80, 1808, 0, WIN_4KB)]);

    let mut syn_ack = TcpPacket::syn(1808, 80, 4000, WIN_4KB).with_mss(400);
    syn_ack.flags.insert(TcpFlags::ACK);
    syn_ack.ack_no = 1;

    test.incoming(syn_ack)?;
    test.assert_outgoing_eq(&[TcpPacket::new(80, 1808, 1, 4001, WIN_4KB, Vec::new())]);
    assert_eq!(test.cong.mss, 400);

    Ok(())
}

#[test]
fn connect_rst_in_syn_sent() -> io::Result<()> {
    let mut test = TcpTestUnit::new(
        SocketAddr::new(Ipv4Addr::new(10, 0, 1, 104).into(), 80), // local
        SocketAddr::new(Ipv4Addr::new(20, 0, 2, 204).into(), 1808), // peer
    );

    test.connect()?;
    test.assert_outgoing_eq(&[TcpPacket::syn(80, 1808, 0, WIN_4KB)]);

    let rst = TcpPacket::rst_for_syn(&TcpPacket::syn(80, 1808, 0, WIN_4KB));
    test.incoming(rst)?;
    test.assert_outgoing_eq(&[]);
    assert_eq!(test.state, State::Closed);

    Ok(())
}

#[test]
fn connect_simultaneous_open() -> io::Result<()> {
    let mut test = TcpTestUnit::new(
        SocketAddr::new(Ipv4Addr::new(10, 0, 1, 104).into(), 80), // local
        SocketAddr::new(Ipv4Addr::new(20, 0, 2, 204).into(), 1808), // peer
    );

    test.connect()?;
    test.assert_outgoing_eq(&[TcpPacket::syn(80, 1808, 0, WIN_4KB)]);

    let syn = TcpPacket::syn(1808, 80, 4000, WIN_4KB);
    let syn_ack = TcpPacket::syn_ack(&syn, 0, WIN_4KB);

    test.incoming(syn)?;
    test.assert_outgoing_eq(&[syn_ack]);
    assert_eq!(test.state, State::SynRcvd);

    test.incoming(TcpPacket::new(1808, 80, 4001, 1, WIN_4KB, Vec::new()))?;
    assert_eq!(test.state, State::Estab);

    Ok(())
}

#[test]
fn accept_syn_ack_lost() -> io::Result<()> {
    let mut test = TcpTestUnit::new(
        SocketAddr::new(Ipv4Addr::new(10, 0, 1, 104).into(), 80), // local
        SocketAddr::new(Ipv4Addr::new(20, 0, 2, 204).into(), 1808), // peer
    );

    // -> SYN
    // <- SYN ACK (lost)
    test.incoming(TcpPacket::syn(1808, 80, 4000, WIN_4KB))?;
    test.assert_outgoing_eq(&[TcpPacket::syn_ack(
        &TcpPacket::syn(1808, 80, 4000, WIN_4KB),
        0,
        WIN_4KB,
    )]);

    // -> SYN (resend from client)
    // <- SYN ACK
    test.incoming(TcpPacket::syn(1808, 80, 4000, WIN_4KB))?;
    test.assert_outgoing_eq(&[TcpPacket::syn_ack(
        &TcpPacket::syn(1808, 80, 4000, WIN_4KB),
        0,
        WIN_4KB,
    )]);

    // -> ACK
    test.incoming(TcpPacket::new(1808, 80, 4001, 1, WIN_4KB, Vec::new()))?;
    assert_eq!(test.state, State::Estab);

    Ok(())
}

#[test]
fn accept_final_ack_lost() -> io::Result<()> {
    let mut test = TcpTestUnit::new(
        SocketAddr::new(Ipv4Addr::new(10, 0, 1, 104).into(), 80), // local
        SocketAddr::new(Ipv4Addr::new(20, 0, 2, 204).into(), 1808), // peer
    );

    // -> SYN
    // <- SYN ACK
    test.incoming(TcpPacket::syn(1808, 80, 4000, WIN_4KB))?;
    test.assert_outgoing_eq(&[TcpPacket::syn_ack(
        &TcpPacket::syn(1808, 80, 4000, WIN_4KB),
        0,
        WIN_4KB,
    )]);

    test.set_time(15.0);

    // <- SYN ACK (since no ACK was recv)
    test.tick()?;
    test.assert_outgoing_eq(&[TcpPacket::syn_ack(
        &TcpPacket::syn(1808, 80, 4000, WIN_4KB),
        0,
        WIN_4KB,
    )]);

    // -> ACK
    test.incoming(TcpPacket::new(1880, 80, 4001, 1, WIN_4KB, Vec::new()))?;
    test.assert_outgoing_eq(&[]);
    assert_eq!(test.state, State::Estab);

    Ok(())
}

#[test]
fn e2e_simultaneous_open() -> io::Result<()> {
    let mut client = TcpTestUnit::new(
        SocketAddr::new(Ipv4Addr::new(10, 0, 1, 104).into(), 80), // local
        SocketAddr::new(Ipv4Addr::new(20, 0, 2, 204).into(), 1808), // peer
    );
    let mut server = TcpTestUnit::new(
        SocketAddr::new(Ipv4Addr::new(20, 0, 2, 204).into(), 1808), // local
        SocketAddr::new(Ipv4Addr::new(10, 0, 1, 104).into(), 80),   // peer
    );

    client.cfg.iss = Some(2000);
    server.cfg.iss = Some(8000);

    client.connect()?;
    client.assert_connection_exists();

    server.connect()?;
    server.assert_connection_exists();

    // -> SYN
    // <- SYN
    client.pipe_and_expect(&mut server, 1, &[TcpPacket::syn(80, 1808, 2000, WIN_4KB)])?;
    server.pipe_and_expect(&mut client, 1, &[TcpPacket::syn(1808, 80, 8000, WIN_4KB)])?;

    assert_eq!(client.state, State::SynRcvd);
    assert_eq!(server.state, State::SynRcvd);

    // -> SYN-ACK
    // <- SYN-ACK
    let syn_ack_for_client_syn =
        TcpPacket::syn_ack(&TcpPacket::syn(80, 1808, 2000, WIN_4KB), 8000, WIN_4KB);
    let syn_ack_for_server_syn =
        TcpPacket::syn_ack(&TcpPacket::syn(1808, 80, 8000, WIN_4KB), 2000, WIN_4KB);
    client.pipe_and_expect(&mut server, 1, &[syn_ack_for_server_syn])?;
    server.pipe_and_expect(&mut client, 1, &[syn_ack_for_client_syn])?;

    // NO ACK is required
    client.assert_outgoing_eq(&[]);
    server.assert_outgoing_eq(&[]);

    assert_eq!(client.state, State::Estab);
    assert_eq!(server.state, State::Estab);

    Ok(())
}

#[test]
fn e2e_normal() -> io::Result<()> {
    let mut client = TcpTestUnit::new(
        SocketAddr::new(Ipv4Addr::new(10, 0, 1, 104).into(), 80), // local
        SocketAddr::new(Ipv4Addr::new(20, 0, 2, 204).into(), 1808), // peer
    );
    let mut server = TcpTestUnit::new(
        SocketAddr::new(Ipv4Addr::new(20, 0, 2, 204).into(), 1808), // local
        SocketAddr::new(Ipv4Addr::new(10, 0, 1, 104).into(), 80),   // peer
    );

    client.connect()?;
    client.assert_connection_exists();

    // client -> server :: SYN
    client.pipe(&mut server, 1)?;
    client.assert_outgoing_eq(&[]);

    // server -> client SYN ACK
    server.pipe(&mut client, 1)?;
    server.assert_outgoing_eq(&[]);
    assert_eq!(client.state, State::Estab);

    client.pipe(&mut server, 1)?;
    client.assert_outgoing_eq(&[]);
    assert_eq!(server.state, State::Estab);

    Ok(())
}
