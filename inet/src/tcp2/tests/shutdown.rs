use std::{
    io,
    net::{Ipv4Addr, SocketAddr},
};

use types::tcp::TcpPacket;

use crate::tcp2::{
    tests::{TcpTestUnit, WIN_4KB},
    State,
};

#[test]
fn e2e_client_close() -> io::Result<()> {
    let mut client = TcpTestUnit::new(
        SocketAddr::new(Ipv4Addr::new(10, 0, 1, 104).into(), 80), // local
        SocketAddr::new(Ipv4Addr::new(20, 0, 2, 204).into(), 1808), // peer
    );
    let mut server = TcpTestUnit::new(
        SocketAddr::new(Ipv4Addr::new(20, 0, 2, 204).into(), 1808), // local
        SocketAddr::new(Ipv4Addr::new(10, 0, 1, 104).into(), 80),   // peer
    );

    client.handshake_pipe(&mut server)?;

    // -> FIN
    client.close()?;
    client.tick()?;
    client.pipe(&mut server, 1)?;

    // <- ACK of FIN
    server.pipe(&mut client, 1)?;
    client.assert_outgoing_eq(&[]);

    // <- FIN
    server.close()?;
    server.tick()?;
    server.pipe(&mut client, 1)?;

    // -> ACK of FIN
    client.pipe(&mut server, 1)?;

    assert_eq!(client.state, State::TimeWait);
    assert_eq!(server.state, State::Closed);

    Ok(())
}

#[test]
fn e2e_server_close() -> io::Result<()> {
    let mut client = TcpTestUnit::new(
        SocketAddr::new(Ipv4Addr::new(10, 0, 1, 104).into(), 80), // local
        SocketAddr::new(Ipv4Addr::new(20, 0, 2, 204).into(), 1808), // peer
    );
    let mut server = TcpTestUnit::new(
        SocketAddr::new(Ipv4Addr::new(20, 0, 2, 204).into(), 1808), // local
        SocketAddr::new(Ipv4Addr::new(10, 0, 1, 104).into(), 80),   // peer
    );

    client.handshake_pipe(&mut server)?;

    // <- FIN
    server.close()?;
    server.tick()?;
    server.pipe(&mut client, 1)?;

    // -> ACK of FIN
    client.pipe(&mut server, 1)?;
    server.assert_outgoing_eq(&[]);

    // -> FIN
    client.close()?;
    client.tick()?;
    client.pipe(&mut server, 1)?;

    // <- ACK of FIN
    server.pipe(&mut client, 1)?;

    assert_eq!(client.state, State::Closed);
    assert_eq!(server.state, State::TimeWait);

    Ok(())
}

#[test]
fn active_close_without_remaining_data() -> io::Result<()> {
    let mut test = TcpTestUnit::new(
        SocketAddr::new(Ipv4Addr::new(10, 0, 1, 104).into(), 80), // local
        SocketAddr::new(Ipv4Addr::new(20, 0, 2, 204).into(), 1808), // peer
    );

    test.handshake(4000, WIN_4KB)?;

    test.close()?;
    test.assert_outgoing_eq(&[]);

    // <- FIN
    test.tick()?;
    test.assert_outgoing_eq(&[TcpPacket::new(80, 1808, 1, 4001, WIN_4KB, Vec::new()).fin(true)]);
    assert_eq!(test.state, State::FinWait1);

    // -> ACK of FIN
    test.incoming(TcpPacket::new(1808, 80, 4001, 2, WIN_4KB, Vec::new()))?;
    test.assert_outgoing_eq(&[]);
    assert_eq!(test.state, State::FinWait2);

    // -> FIN
    // <- ACK of FIN
    test.incoming(TcpPacket::new(1808, 80, 4001, 2, WIN_4KB, Vec::new()).fin(true))?;
    test.assert_outgoing_eq(&[TcpPacket::new(80, 1808, 2, 4002, WIN_4KB, Vec::new())]);
    assert_eq!(test.state, State::TimeWait);

    Ok(())
}

#[test]
fn active_close_with_remaining_data() -> io::Result<()> {
    let mut test = TcpTestUnit::new(
        SocketAddr::new(Ipv4Addr::new(10, 0, 1, 104).into(), 80), // local
        SocketAddr::new(Ipv4Addr::new(20, 0, 2, 204).into(), 1808), // peer
    );

    test.handshake(4000, WIN_4KB)?;

    test.write(&[1, 2, 3, 4, 5, 6, 7, 8])?;
    test.close()?;
    test.assert_outgoing_eq(&[]);
    assert_eq!(test.state, State::FinWait1);

    // <- FIN with 8 bytes
    test.tick()?;
    test.assert_outgoing_eq(&[
        // Data packet with attached FIN
        TcpPacket::new(80, 1808, 1, 4001, WIN_4KB, vec![1, 2, 3, 4, 5, 6, 7, 8]).fin(true),
    ]);
    assert_eq!(test.state, State::FinWait1);

    // -> ACK if FIN (ack := 1 + 8 bytes + 1 FIN)
    test.incoming(TcpPacket::new(1808, 80, 4001, 10, WIN_4KB, Vec::new()))?;
    assert_eq!(test.state, State::FinWait2);

    test.incoming(TcpPacket::new(1808, 80, 4001, 10, WIN_4KB, Vec::new()).fin(true))?;
    test.assert_outgoing_eq(&[TcpPacket::new(80, 1808, 10, 4002, WIN_4KB, Vec::new())]);
    assert_eq!(test.state, State::TimeWait);

    Ok(())
}

#[test]
fn active_close_initial_fin_lost() -> io::Result<()> {
    let mut test = TcpTestUnit::new(
        SocketAddr::new(Ipv4Addr::new(10, 0, 1, 104).into(), 80), // local
        SocketAddr::new(Ipv4Addr::new(20, 0, 2, 204).into(), 1808), // peer
    );

    test.handshake(4000, WIN_4KB)?;

    // <- FIN (lost)
    test.close()?;
    test.tick()?;
    test.clear_outgoing();

    // NOP
    test.tick()?;
    test.assert_outgoing_eq(&[]);

    // <- FIN (retransmit)
    test.set_time(15.0);
    test.tick()?;
    test.assert_outgoing_eq(&[TcpPacket::new(80, 1808, 1, 4001, WIN_4KB, Vec::new()).fin(true)]);

    assert_eq!(test.state, State::FinWait1);

    Ok(())
}

#[test]
fn passive_close_without_remaining_data() -> io::Result<()> {
    let mut test = TcpTestUnit::new(
        SocketAddr::new(Ipv4Addr::new(10, 0, 1, 104).into(), 80), // local
        SocketAddr::new(Ipv4Addr::new(20, 0, 2, 204).into(), 1808), // peer
    );

    test.handshake(4000, WIN_4KB)?;

    // -> FIN
    // <- ACK of FIN
    test.incoming(TcpPacket::new(1808, 80, 4001, 1, WIN_4KB, Vec::new()).fin(true))?;
    test.assert_outgoing_eq(&[TcpPacket::new(80, 1808, 1, 4002, WIN_4KB, Vec::new())]);
    assert_eq!(test.state, State::CloseWait);

    // <- FIN
    test.close()?;
    test.tick()?;
    test.assert_outgoing_eq(&[TcpPacket::new(80, 1808, 1, 4002, WIN_4KB, Vec::new()).fin(true)]);
    assert_eq!(test.state, State::LastAck);

    // -> ACK of FIN
    test.incoming(TcpPacket::new(1808, 80, 4002, 2, WIN_4KB, Vec::new()))?;
    test.assert_outgoing_eq(&[]);
    assert_eq!(test.state, State::Closed);

    Ok(())
}

#[test]
fn passive_close_with_remaining_data() -> io::Result<()> {
    let mut test = TcpTestUnit::new(
        SocketAddr::new(Ipv4Addr::new(10, 0, 1, 104).into(), 80), // local
        SocketAddr::new(Ipv4Addr::new(20, 0, 2, 204).into(), 1808), // peer
    );

    test.handshake(4000, WIN_4KB)?;

    // -> FIN
    // <- ACK of FIN
    test.incoming(
        TcpPacket::new(1808, 80, 4001, 1, WIN_4KB, vec![1, 2, 3, 4, 5, 6, 7, 8]).fin(true),
    )?;
    test.assert_outgoing_eq(&[
        TcpPacket::new(80, 1808, 1, 4009, WIN_4KB - 8, Vec::new()),
        TcpPacket::new(80, 1808, 1, 4010, WIN_4KB - 8, Vec::new()),
    ]);
    assert_eq!(test.state, State::CloseWait);

    // <- FIN
    test.close()?;
    test.tick()?;
    test.assert_outgoing_eq(
        &[TcpPacket::new(80, 1808, 1, 4010, WIN_4KB - 8, Vec::new()).fin(true)],
    );
    assert_eq!(test.state, State::LastAck);

    // -> ACK of FIN
    test.incoming(TcpPacket::new(1808, 80, 4010, 2, WIN_4KB, Vec::new()))?;
    test.assert_outgoing_eq(&[]);
    assert_eq!(test.state, State::Closed);

    Ok(())
}

#[test]
fn passive_close_secondary_fin_lost() -> io::Result<()> {
    let mut test = TcpTestUnit::new(
        SocketAddr::new(Ipv4Addr::new(10, 0, 1, 104).into(), 80), // local
        SocketAddr::new(Ipv4Addr::new(20, 0, 2, 204).into(), 1808), // peer
    );

    test.handshake(4000, WIN_4KB)?;

    // -> FIN
    // <- ACK of FIN
    test.incoming(TcpPacket::new(1808, 80, 4001, 1, WIN_4KB, Vec::new()).fin(true))?;
    test.assert_outgoing_eq(&[TcpPacket::new(80, 1808, 1, 4002, WIN_4KB, Vec::new())]);

    // <- FIN (lost)
    test.close()?;
    test.tick()?;
    test.assert_outgoing_eq(&[TcpPacket::new(80, 1808, 1, 4002, WIN_4KB, Vec::new()).fin(true)]);

    // <- FIN
    test.set_time(15.0);
    test.tick()?;
    test.assert_outgoing_eq(&[TcpPacket::new(80, 1808, 1, 4002, WIN_4KB, Vec::new()).fin(true)]);

    assert_eq!(test.state, State::LastAck);

    Ok(())
}

#[test]
fn passive_close_ack_of_fin_lost() -> io::Result<()> {
    let mut test = TcpTestUnit::new(
        SocketAddr::new(Ipv4Addr::new(10, 0, 1, 104).into(), 80), // local
        SocketAddr::new(Ipv4Addr::new(20, 0, 2, 204).into(), 1808), // peer
    );

    test.handshake(4000, WIN_4KB)?;

    // -> FIN
    // <- ACK of FIN
    test.incoming(TcpPacket::new(1808, 80, 4001, 1, WIN_4KB, Vec::new()).fin(true))?;
    test.clear_outgoing();

    // -> FIN (since ACK was lost)
    test.incoming(TcpPacket::new(1808, 80, 4001, 1, WIN_4KB, Vec::new()).fin(true))?;
    test.assert_outgoing_eq(&[TcpPacket::new(80, 1808, 1, 4002, WIN_4KB, Vec::new())]);
    assert_eq!(test.state, State::CloseWait);

    Ok(())
}

#[test]
fn e2e_simultaneous_close() -> io::Result<()> {
    let mut client = TcpTestUnit::new(
        SocketAddr::new(Ipv4Addr::new(10, 0, 1, 104).into(), 80), // local
        SocketAddr::new(Ipv4Addr::new(20, 0, 2, 204).into(), 1808), // peer
    );
    let mut server = TcpTestUnit::new(
        SocketAddr::new(Ipv4Addr::new(20, 0, 2, 204).into(), 1808), // local
        SocketAddr::new(Ipv4Addr::new(10, 0, 1, 104).into(), 80),   // peer
    );

    client.handshake_pipe(&mut server)?;

    client.close()?;
    client.tick()?;

    server.close()?;
    server.tick()?;

    // -> FIN
    client.pipe(&mut server, 1)?;

    // <- FIN
    // <- ACK of FIN
    server.pipe(&mut client, 2)?;

    // -> ACK of FIN
    client.pipe(&mut server, 1)?;

    assert_eq!(client.state, State::TimeWait);
    assert_eq!(server.state, State::TimeWait);

    Ok(())
}

#[test]
fn simultaneous_close_syn_before_ack() -> io::Result<()> {
    let mut test = TcpTestUnit::new(
        SocketAddr::new(Ipv4Addr::new(10, 0, 1, 104).into(), 80), // local
        SocketAddr::new(Ipv4Addr::new(20, 0, 2, 204).into(), 1808), // peer
    );

    test.handshake(4000, WIN_4KB)?;

    // <- FIN
    test.close()?;
    test.tick()?;
    test.assert_outgoing_eq(&[TcpPacket::new(80, 1808, 1, 4001, WIN_4KB, Vec::new()).fin(true)]);

    // -> FIN
    // <- ACK of FIN
    test.incoming(TcpPacket::new(1808, 80, 4001, 1, WIN_4KB, Vec::new()).fin(true))?;
    test.assert_outgoing_eq(&[TcpPacket::new(80, 1808, 2, 4002, WIN_4KB, Vec::new())]);

    // -> ACK of FIN
    test.incoming(TcpPacket::new(1808, 80, 4002, 2, WIN_4KB, Vec::new()))?;
    assert_eq!(test.state, State::TimeWait);

    Ok(())
}

#[test]
fn active_close_lost_fin_with_data() -> io::Result<()> {
    let mut test = TcpTestUnit::new(
        SocketAddr::new(Ipv4Addr::new(10, 0, 1, 104).into(), 80), // local
        SocketAddr::new(Ipv4Addr::new(20, 0, 2, 204).into(), 1808), // peer
    );

    test.handshake(4000, WIN_4KB)?;

    // <- FIN with data (lost)
    test.write(&[1, 2, 3, 4, 5, 6, 7, 8])?;
    test.close()?;
    test.tick()?;
    test.assert_outgoing_eq(&[TcpPacket::new(
        80,
        1808,
        1,
        4001,
        WIN_4KB,
        vec![1, 2, 3, 4, 5, 6, 7, 8],
    )
    .fin(true)]);

    // <- FIN with data (retransmit)
    test.set_time(15.0);
    test.tick()?;
    test.assert_outgoing_eq(&[TcpPacket::new(
        80,
        1808,
        1,
        4001,
        WIN_4KB,
        vec![1, 2, 3, 4, 5, 6, 7, 8],
    )
    .fin(true)]);

    // -> ACK of FIN
    test.incoming(TcpPacket::new(1808, 80, 4001, 10, WIN_4KB, Vec::new()))?;
    test.assert_outgoing_eq(&[]);
    assert_eq!(test.state, State::FinWait2);

    Ok(())
}
