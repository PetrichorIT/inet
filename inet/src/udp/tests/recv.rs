use std::{io, net::Ipv4Addr, time::Duration};

use des::{runtime::RuntimeError, time::sleep};
use serial_test::serial;

use crate::{test_util::SimpleSim, UdpSocket};

#[test]
#[serial]
fn recv_truncates_packets() -> Result<(), RuntimeError> {
    let mut sim = SimpleSim::new(crate::init);
    sim.node_require_join("192.168.2.100", || async move {
        let sock = UdpSocket::bind("0.0.0.0:100").await?;
        let mut buf = [0u8; 100];

        let (n, _) = sock.recv_from(&mut buf).await?;
        assert_eq!(n, 100);
        assert_eq!(buf, [2; 100]);

        sleep(Duration::from_secs(1)).await;
        assert_eq!(
            sock.try_recv_from(&mut [0])
                .expect_err("expected an err")
                .kind(),
            io::ErrorKind::WouldBlock
        );

        Ok(())
    });

    sim.node_require_join("sender", || async move {
        UdpSocket::bind("0.0.0.0:201")
            .await?
            .send_to(&[2; 200], "192.168.2.100:100")
            .await?;
        Ok(())
    });

    sim.run()
}

#[test]
#[serial]
fn recv_from_ignores_other_packets() -> Result<(), RuntimeError> {
    let mut sim = SimpleSim::new(crate::init);
    sim.node_require_join("192.168.2.100", || async move {
        let sock = UdpSocket::bind("0.0.0.0:100").await?;
        sock.connect("192.168.2.101:100").await?;
        let mut buf = [0u8; 100];

        let n = sock.recv(&mut buf).await?;
        assert_eq!(n, 100);
        assert_eq!(buf, [2; 100]);

        sleep(Duration::from_secs(1)).await;
        assert_eq!(
            sock.try_recv(&mut [0]).expect_err("expected an err").kind(),
            io::ErrorKind::WouldBlock
        );

        Ok(())
    });

    sim.node_require_join("192.168.2.101", || async move {
        UdpSocket::bind("0.0.0.0:100")
            .await?
            .send_to(&[2; 200], "192.168.2.100:100")
            .await?;
        Ok(())
    });

    sim.node_require_join("other", || async move {
        UdpSocket::bind("0.0.0.0:201")
            .await?
            .send_to(&[5; 200], "192.168.2.100:100")
            .await?;
        Ok(())
    });

    sim.run()
}

#[test]
#[serial]
fn recv_from_default_to_recv_when_connected() -> Result<(), RuntimeError> {
    let mut sim = SimpleSim::new(crate::init);

    sim.node_require_join("192.168.2.100", || async move {
        let udp = UdpSocket::bind("0.0.0.0:100").await?;
        udp.connect("192.168.2.101:101").await?;

        let mut buf = [0u8; 100];
        let (_, from) = udp.recv_from(&mut buf).await?;
        assert_eq!(from.ip(), Ipv4Addr::new(192, 168, 2, 101));

        sleep(Duration::from_secs(1)).await;

        assert_eq!(
            udp.try_recv_from(&mut [0])
                .expect_err("expected an err")
                .kind(),
            io::ErrorKind::WouldBlock
        );

        Ok(())
    });

    sim.node_require_join("192.168.2.101", || async move {
        UdpSocket::bind("0.0.0.0:101")
            .await?
            .send_to(&[1], "192.168.2.100:100")
            .await?;
        Ok(())
    });

    sim.node_require_join("192.168.2.102", || async move {
        UdpSocket::bind("0.0.0.0:102")
            .await?
            .send_to(&[2], "192.168.2.100:100")
            .await?;
        Ok(())
    });

    sim.run()
}

#[test]
#[serial]
fn peek_preserves_packets() -> Result<(), RuntimeError> {
    let mut sim = SimpleSim::new(crate::init);

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
