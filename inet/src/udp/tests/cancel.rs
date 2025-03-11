use std::time::Duration;

use des::{runtime::RuntimeError, time::sleep};
use serial_test::serial;

use crate::{test_util::SimpleSim, UdpSocket};

#[test]
#[serial]
fn select_recv_two_sockets() -> Result<(), RuntimeError> {
    let mut sim = SimpleSim::new(crate::init);
    sim.node_require_join("192.168.2.100", || async move {
        let a = UdpSocket::bind("0.0.0.0:100").await?;
        let b = UdpSocket::bind("0.0.0.0:101").await?;

        let mut buf_a = [0u8; 1024];
        let mut buf_b = [0u8; 1024];

        let mut total = 0;
        for _ in 0..3 {
            let (n, _) = tokio::select! {
                frame = a.recv_from(&mut buf_a) => frame?,
                frame = b.recv_from(&mut buf_b) => frame?,
            };

            total += n;
        }

        assert_eq!(total, 111);
        Ok(())
    });

    sim.node_require_join("a", || async move {
        let sock = UdpSocket::bind("0.0.0.0:0").await?;
        sock.connect("192.168.2.100:100").await?;

        sock.send(&[1; 100]).await?;
        sock.send(&[100]).await?;

        Ok(())
    });

    sim.node_require_join("b", || async move {
        let sock = UdpSocket::bind("0.0.0.0:0").await?;
        sock.connect("192.168.2.100:101").await?;

        sock.send(&[10; 10]).await?;

        Ok(())
    });

    sim.run()
}

#[test]
#[serial]
fn select_recv_send() -> Result<(), RuntimeError> {
    let mut sim = SimpleSim::new(crate::init);
    sim.metrics.bitrate = 5_000;
    sim.metrics.latency = Duration::from_micros(5);

    sim.node_require_join("192.168.2.100", || async move {
        // Update ARP entries, to ensure correct send behaviour
        UdpSocket::bind("0.0.0.0:0")
            .await?
            .send_to(&[1], "192.168.2.101:1")
            .await?;

        sleep(Duration::from_secs(2)).await;
        let sock = UdpSocket::bind("0.0.0.0:100").await?;

        let mut snd = vec![
            &[100; 1300],
            &[100; 1300],
            &[100; 1300],
            &[100; 1300],
            &[100; 1300],
        ];
        let mut buf = [0u8; 1024];

        let mut recv = 0;
        for _ in 0..6 {
            tokio::select! {
                frame = sock.recv_from(&mut buf) => {
                    recv += frame?.0;
                },
                frame = sock.send_to(snd[0], "192.168.2.101:1") => {
                    frame?;
                    snd.remove(0);
                },
            };
        }

        assert_eq!(recv, 100);
        Ok(())
    });

    sim.node_require_join("192.168.2.101", || async move {
        sleep(Duration::from_secs(2)).await;

        let sock = UdpSocket::bind("0.0.0.0:0").await?;
        sock.send_to(&[1; 100], "192.168.2.100:100").await?;

        Ok(())
    });

    sim.run()
}
