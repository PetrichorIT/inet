use serial_test::serial;
use std::io;

use crate::{UdpSocket, interface::InterfaceDef, ioctx, utils::SimpleSim};
use des::{prelude::*, random, time::sleep};

//
// Broadcast behaviour
//
// Sender should also receive packets, when bound to 0.0.0.0
// Packet SRC should be get_ip() the actual sender IP
//
// If bound to get_ip() no recv allowed
//

#[test]
#[serial]
fn deny_broadcast_without_option() -> Result<(), des::Failure> {
    let mut sim = SimpleSim::default();
    sim.node_require_join("alice", || async move {
        let udp = UdpSocket::bind("0.0.0.0:0").await?;
        let error = udp
            .send_to(&[1, 2, 3], "255.255.255.255:200")
            .await
            .expect_err("must be an error");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);

        Ok(())
    });

    sim.run()
}

#[test]
#[serial]
fn default_no_broadcast() -> Result<(), des::Failure> {
    let mut sim = SimpleSim::default();
    sim.node_require_join("alice", || async move {
        let udp = UdpSocket::bind("0.0.0.0:0").await?;
        assert_eq!(udp.broadcast()?, false);

        Ok(())
    });

    sim.run()
}

#[test]
#[serial]
fn broadcast_no_loopback() -> Result<(), des::Failure> {
    let mut sim = SimpleSim::default();

    let nodes = vec![
        Ipv4Addr::new(192, 168, 2, 101),
        Ipv4Addr::new(192, 168, 2, 102),
        Ipv4Addr::new(192, 168, 2, 103),
        Ipv4Addr::new(192, 168, 2, 104),
        Ipv4Addr::new(192, 168, 2, 105),
    ];
    let packets = vec![
        vec![100, 20, 90],
        vec![300, 600],
        vec![100, 20, 90],
        vec![],
        vec![300, 80, 10],
    ];

    let total_expected = packets.iter().flatten().sum::<usize>();
    let expected = packets
        .iter()
        .map(|self_send| total_expected - self_send.iter().sum::<usize>())
        .collect::<Vec<_>>();

    for ((addr, packets), expected) in nodes.into_iter().zip(packets).zip(expected) {
        sim.node_require_join(&addr.to_string(), move || {
            let packets = packets.clone();
            async move {
                let sender = tokio::spawn(async move {
                    let udp = UdpSocket::bind("0.0.0.0:0").await?;
                    udp.set_broadcast(true)?;

                    assert_eq!(udp.broadcast()?, true);

                    for pkt in packets {
                        sleep(Duration::from_secs_f64(random())).await;
                        let buf = vec![42; pkt];
                        tracing::info!("broadcasting {pkt} bytes");
                        udp.send_to(&buf, "255.255.255.255:100").await?;
                    }

                    Ok::<_, io::Error>(())
                });

                let udp = UdpSocket::bind("0.0.0.0:100").await?;
                let mut remaining = expected;
                let mut buf = vec![0; 1024];
                while remaining > 0 {
                    let (len, from) = udp.recv_from(&mut buf).await?;
                    tracing::info!("recieved {len} bytes from {}", from.ip());
                    remaining -= len;
                }

                sender.await??;
                Ok(())
            }
        });
    }

    sim.run()
}

#[test]
#[serial]
fn broadcast_with_loopback() -> Result<(), des::Failure> {
    // des::tracing::init();

    let mut sim = SimpleSim::default();

    let nodes = vec![
        Ipv4Addr::new(192, 168, 2, 101),
        Ipv4Addr::new(192, 168, 2, 102),
        Ipv4Addr::new(192, 168, 2, 103),
        Ipv4Addr::new(192, 168, 2, 104),
        Ipv4Addr::new(192, 168, 2, 105),
    ];
    let packets = vec![
        vec![100, 20, 90],
        vec![300, 600],
        vec![100, 20, 90],
        vec![],
        vec![300, 80, 10],
    ];

    let total_expected = packets.iter().flatten().sum::<usize>();

    for (addr, packets) in nodes.into_iter().zip(packets) {
        sim.node_require_join(&addr.to_string(), move || {
            let packets = packets.clone();
            async move {
                ioctx().add_interface(InterfaceDef::loopback())?;

                let sender = tokio::spawn(async move {
                    let udp = UdpSocket::bind("0.0.0.0:0").await?;
                    udp.set_broadcast(true)?;

                    for pkt in packets {
                        sleep(Duration::from_secs_f64(random())).await;
                        let buf = vec![42; pkt];
                        tracing::info!("broadcasting {pkt} bytes");
                        udp.send_to(&buf, "255.255.255.255:100").await?;
                    }

                    Ok::<_, io::Error>(())
                });

                let udp = UdpSocket::bind("0.0.0.0:100").await?;
                let mut remaining = total_expected;
                let mut buf = vec![0; 1024];
                while remaining > 0 {
                    let (len, from) = udp.recv_from(&mut buf).await?;
                    tracing::info!("recieved {len} bytes from {}", from.ip());
                    remaining -= len;
                }

                sender.await??;
                Ok(())
            }
        });
    }

    sim.run()
}

/// TODO: This is not correct, behaviour a global addr should be assigned if possible
#[test]
#[serial]
fn broadcast_loopback_assigns_lo_addr() -> Result<(), des::Failure> {
    // des::tracing::init();

    let mut sim = SimpleSim::default();
    sim.node_require_join("192.168.2.100", || async move {
        ioctx().add_interface(InterfaceDef::loopback())?;

        let h = tokio::spawn(async move {
            sleep(Duration::from_secs(1)).await;
            let udp = UdpSocket::bind("0.0.0.0:0").await?;
            udp.set_broadcast(true)?;
            udp.send_to(&[1; 100], "255.255.255.255:200").await?;
            Ok::<_, io::Error>(())
        });

        let udp = UdpSocket::bind("0.0.0.0:200").await?;
        let mut buf = [0; 1024];
        let (n, from) = udp.recv_from(&mut buf).await?;

        assert_eq!(n, 100);
        assert_eq!(from.ip(), Ipv4Addr::new(127, 0, 0, 1));

        h.await??;

        Ok(())
    });

    sim.run()
}
