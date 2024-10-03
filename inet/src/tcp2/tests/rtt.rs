use std::{
    io,
    net::{Ipv4Addr, SocketAddr},
};

use inet_types::tcp::TcpPacket;

use super::{TcpTestUnit, WIN_4KB};

#[test]
fn probing_via_data_acks() -> io::Result<()> {
    let mut test = TcpTestUnit::new(
        SocketAddr::new(Ipv4Addr::new(10, 0, 1, 104).into(), 80), // local
        SocketAddr::new(Ipv4Addr::new(20, 0, 2, 204).into(), 1808), // peer
    );

    test.handshake(4000, WIN_4KB)?;

    for i in 0..10 {
        // <- DATA
        test.write(&[i as u8])?;
        test.tick()?;
        test.assert_outgoing_eq(&[TcpPacket::new(
            80,
            1808,
            1 + i,
            4001,
            WIN_4KB,
            vec![i as u8],
        )]);

        // -> ACK
        test.set_time((i + 1) as f64);
        test.incoming(TcpPacket::new(
            1808,
            80,
            4001,
            2 + i,
            WIN_4KB - i as u16,
            Vec::new(),
        ))?;
        test.tick()?;
        test.assert_outgoing_eq(&[]);
    }

    assert_eq!(test.timers.srtt, 1.9663676416000002);

    Ok(())
}
