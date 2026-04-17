use std::{
    io::{self, ErrorKind},
    net::Ipv4Addr,
};

use des::time::sleep_until;
use serial_test::serial;

use crate::{UdpSocket, utils::SimpleSim};

#[test]
#[serial]
fn peek_from_preserves_packets() -> Result<(), des::Failure> {
    let mut sim = SimpleSim::default();

    sim.node_require_join("192.168.2.100", || async move {
        let udp = UdpSocket::bind("0.0.0.0:100").await?;

        for _ in 0..3 {
            let mut buf = [0u8; 100];
            let (n, from) = udp.peek_from(&mut buf).await?;
            assert_eq!(n, 1);
            assert_eq!(from.ip(), Ipv4Addr::new(192, 168, 2, 101));
        }

        udp.recv_from(&mut [0]).await?;

        assert_eq!(
            udp.try_peek_from(&mut [0])
                .expect_err("expected an err")
                .kind(),
            io::ErrorKind::WouldBlock
        );

        Ok(())
    });

    sim.node_require_join("192.168.2.101", || async move {
        UdpSocket::bind("0.0.0.0:0")
            .await?
            .send_to(&[1], "192.168.2.100:100")
            .await?;
        Ok(())
    });

    sim.run()
}

#[test]
#[serial]
fn peek_on_connected() -> Result<(), des::Failure> {
    let mut sim = SimpleSim::default();
    sim.node("192.168.2.101", || async move {
        let sock = UdpSocket::bind("0.0.0.0:80").await?;
        sock.connect("192.168.2.102:90").await?;

        let mut buf = [0; 1024];

        let err = sock.try_peek(&mut buf).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::WouldBlock);

        let n = sock.peek(&mut buf).await?;
        assert_eq!(&buf[..n], [1, 2, 3]);

        Ok(())
    });

    sim.node("192.168.2.102", || async move {
        let sock = UdpSocket::bind("0.0.0.0:90").await?;
        sock.send_to(&[1, 2, 3], "192.168.2.101:80").await?;
        Ok(())
    });

    sim.run()
}

#[test]
#[serial]
fn peek_sender_on_connected() -> Result<(), des::Failure> {
    let mut sim = SimpleSim::default();
    sim.node("192.168.2.101", || async move {
        let sock = UdpSocket::bind("0.0.0.0:80").await?;

        let err = sock.try_peek_sender().unwrap_err();
        assert_eq!(err.kind(), ErrorKind::WouldBlock);

        sock.readable().await?;
        let sender = sock.try_peek_sender()?;
        assert_eq!(sender, "192.168.2.102:90".parse().unwrap());
        sock.try_recv_from(&mut [0; 1024])?;

        sleep_until(5.0.into()).await;

        let sender = sock.peek_sender().await?;
        assert_eq!(sender, "192.168.2.103:100".parse().unwrap());

        Ok(())
    });

    sim.node("192.168.2.102", || async move {
        let sock = UdpSocket::bind("0.0.0.0:90").await?;
        sock.send_to(&[1, 2, 3], "192.168.2.101:80").await?;

        Ok(())
    });

    sim.node("192.168.2.103", || async move {
        sleep_until(5.0.into()).await;
        let sock = UdpSocket::bind("0.0.0.0:100").await?;
        sock.send_to(&[1, 2, 3], "192.168.2.101:80").await?;
        Ok(())
    });

    sim.run()
}
