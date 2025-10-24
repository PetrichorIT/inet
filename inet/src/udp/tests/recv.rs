use std::{
    io::{self, ErrorKind},
    net::Ipv4Addr,
    time::Duration,
};

use bytes_io::BytesMut;
use des::{runtime::RuntimeError, time::sleep};
use serial_test::serial;

use crate::{UdpSocket, test_util::SimpleSim};

#[test]
#[serial]
fn recv_truncates_packets() -> Result<(), RuntimeError> {
    let mut sim = SimpleSim::default();
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
    let mut sim = SimpleSim::default();
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
fn recv_from_for_connected_socket_default_to_recv() -> Result<(), RuntimeError> {
    let mut sim = SimpleSim::default();
    sim.node_require_join("192.168.2.100", || async move {
        let sock = UdpSocket::bind("0.0.0.0:100").await?;
        sock.connect("192.168.2.101:100").await?;
        let mut buf = [0u8; 100];

        let (n, from) = sock.recv_from(&mut buf).await?;
        assert_eq!(n, 100);
        assert_eq!(buf, [2; 100]);
        assert_eq!(from, "192.168.2.101:100".parse().unwrap());

        sleep(Duration::from_secs(1)).await;
        assert_eq!(
            sock.try_recv_from(&mut [0])
                .expect_err("expected an err")
                .kind(),
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

    sim.run()
}

#[test]
#[serial]
fn recv_from_default_to_recv_when_connected() -> Result<(), RuntimeError> {
    let mut sim = SimpleSim::default();

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
fn try_recv_would_block() -> Result<(), RuntimeError> {
    let mut sim = SimpleSim::default();
    sim.node("192.168.2.101", || async move {
        let sock = UdpSocket::bind("0.0.0.0:80").await?;
        let err = sock.try_recv_buf_from(&mut BytesMut::new()).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::WouldBlock);

        sleep(Duration::from_secs(5)).await;
        let (n, addr) = sock.try_recv_buf_from(&mut BytesMut::new())?;

        assert_eq!(n, 4);
        assert_eq!(addr, "192.168.2.102:1024".parse().unwrap());

        Ok(())
    });

    sim.node("192.168.2.102", || async move {
        let sock = UdpSocket::bind("0.0.0.0:0").await?;
        sleep(Duration::from_secs(3)).await;
        sock.try_send_to(&[1, 2, 3, 5], "192.168.2.101:80".parse().unwrap())?;
        Ok(())
    });

    sim.run()
}
