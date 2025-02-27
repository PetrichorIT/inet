use std::{
    io,
    net::{Ipv4Addr, SocketAddr},
};

use types::tcp::{TcpOption, TcpPacket};

use super::{TcpTestUnit, WIN_4KB};

#[test]
fn disable_sack() -> io::Result<()> {
    let mut test = TcpTestUnit::new(
        SocketAddr::new(Ipv4Addr::new(10, 0, 1, 104).into(), 80), // local
        SocketAddr::new(Ipv4Addr::new(20, 0, 2, 204).into(), 1808), // peer
    );
    test.cfg.enable_sack = false;
    test.handshake(4000, WIN_4KB)?;
    assert!(!test.incoming.sack);

    Ok(())
}

#[test]
fn active_open_enable_sack() -> io::Result<()> {
    let mut test = TcpTestUnit::new(
        SocketAddr::new(Ipv4Addr::new(10, 0, 1, 104).into(), 80), // local
        SocketAddr::new(Ipv4Addr::new(20, 0, 2, 204).into(), 1808), // peer
    );
    test.cfg.enable_sack = true;

    test.connect()?;
    test.assert_outgoing_eq(&[TcpPacket::syn(80, 1808, 0, WIN_4KB)
        .with_option(TcpOption::SelectiveAcknowledgementPermitted)
        .with_option(TcpOption::EndOfOptionsList)]);

    test.incoming(
        TcpPacket::syn_ack(&TcpPacket::syn(80, 1808, 0, WIN_4KB), 4000, WIN_4KB)
            .with_option(TcpOption::SelectiveAcknowledgementPermitted)
            .with_option(TcpOption::EndOfOptionsList),
    )?;
    test.assert_outgoing_eq(&[TcpPacket::new(80, 1808, 1, 4001, WIN_4KB, Vec::new())]);

    assert!(test.incoming.sack);

    Ok(())
}

#[test]
fn passive_open_enable_sack() -> io::Result<()> {
    let mut test = TcpTestUnit::new(
        SocketAddr::new(Ipv4Addr::new(10, 0, 1, 104).into(), 80), // local
        SocketAddr::new(Ipv4Addr::new(20, 0, 2, 204).into(), 1808), // peer
    );
    test.cfg.enable_sack = true;

    test.incoming(
        TcpPacket::syn(1808, 80, 4000, WIN_4KB)
            .with_option(TcpOption::SelectiveAcknowledgementPermitted)
            .with_option(TcpOption::EndOfOptionsList),
    )?;
    test.assert_outgoing_eq(&[TcpPacket::syn_ack(
        &TcpPacket::syn(1808, 80, 4000, WIN_4KB),
        0,
        WIN_4KB,
    )
    .with_option(TcpOption::SelectiveAcknowledgementPermitted)
    .with_option(TcpOption::EndOfOptionsList)]);

    assert!(test.incoming.sack);

    Ok(())
}
