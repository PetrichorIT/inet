use std::{
    collections::HashMap,
    io::{self, ErrorKind},
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    str::FromStr,
    time::Duration,
};

use bytes_io::BytesMut;
use des::{
    runtime::{RuntimeError, random},
    time::sleep,
};
use serial_test::serial;

use crate::{UdpSocket, test_util::SimpleSim};

#[test]
#[serial]
fn ipv4() -> Result<(), RuntimeError> {
    let mut sim = SimpleSim::default();

    let nodes = vec![
        Ipv4Addr::new(192, 168, 2, 101),
        Ipv4Addr::new(192, 168, 2, 102),
        Ipv4Addr::new(192, 168, 2, 103),
        Ipv4Addr::new(192, 168, 2, 104),
        Ipv4Addr::new(192, 168, 2, 105),
    ];
    let packets = vec![
        vec![nodes[1], nodes[3], nodes[4], nodes[3]],
        vec![nodes[3], nodes[2], nodes[0], nodes[0], nodes[4]],
        vec![nodes[0], nodes[0], nodes[3], nodes[4]],
        vec![nodes[1], nodes[1], nodes[4]],
        vec![nodes[2], nodes[1], nodes[0]],
    ];

    let frequencies = packets
        .iter()
        .flatten()
        .fold(HashMap::new(), |mut map, addr| {
            *map.entry(*addr).or_insert(0) += 1;
            map
        });

    for (addr, packets) in nodes.into_iter().zip(packets) {
        let expected = *frequencies.get(&addr).unwrap();
        sim.node_require_join(&addr.to_string(), move || {
            let packets = packets.clone();
            async move {
                let sender = tokio::spawn(async move {
                    let udp = UdpSocket::bind("0.0.0.0:0").await?;

                    for pkt in packets {
                        sleep(Duration::from_secs_f64(random())).await;
                        let buf = vec![42; 100];
                        tracing::info!("broadcasting {pkt} bytes");
                        udp.send_to(&buf, (pkt, 100)).await?;
                    }

                    Ok::<_, io::Error>(())
                });

                let udp = UdpSocket::bind("0.0.0.0:100").await?;
                let mut remaining = expected;
                let mut buf = vec![0; 1024];
                while remaining > 0 {
                    let (len, from) = udp.recv_from(&mut buf).await?;
                    tracing::info!("recieved {len} bytes from {}", from.ip());
                    remaining -= 1;
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
fn ipv6() -> Result<(), RuntimeError> {
    let mut sim = SimpleSim::default();

    let nodes = vec![
        Ipv6Addr::from_str("fe80::aa00")?,
        Ipv6Addr::from_str("fe80::aa01")?,
        Ipv6Addr::from_str("fe80::aa02")?,
        Ipv6Addr::from_str("fe80::aa03")?,
        Ipv6Addr::from_str("fe80::aa04")?,
    ];
    let packets = vec![
        vec![nodes[1], nodes[3], nodes[4], nodes[3]],
        vec![nodes[3], nodes[2], nodes[0], nodes[0], nodes[4]],
        vec![nodes[0], nodes[0], nodes[3], nodes[4]],
        vec![nodes[1], nodes[1], nodes[4]],
        vec![nodes[2], nodes[1], nodes[0]],
    ];

    let frequencies = packets
        .iter()
        .flatten()
        .fold(HashMap::new(), |mut map, addr| {
            *map.entry(*addr).or_insert(0) += 1;
            map
        });

    for (addr, packets) in nodes.into_iter().zip(packets) {
        let expected = *frequencies.get(&addr).unwrap();
        sim.node_require_join(&addr.to_string(), move || {
            let packets = packets.clone();
            async move {
                let sender = tokio::spawn(async move {
                    let udp = UdpSocket::bind(":::0").await?;

                    for pkt in packets {
                        sleep(Duration::from_secs_f64(random())).await;
                        let buf = vec![42; 100];
                        tracing::info!("broadcasting {pkt} bytes");
                        udp.send_to(&buf, (pkt, 100)).await?;
                    }

                    Ok::<_, io::Error>(())
                });

                let udp = UdpSocket::bind(":::100").await?;
                let mut remaining = expected;
                let mut buf = vec![0; 1024];
                while remaining > 0 {
                    let (len, from) = udp.recv_from(&mut buf).await?;
                    tracing::info!("recieved {len} bytes from {}", from.ip());
                    remaining -= 1;
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
fn try_send_blocks() -> Result<(), RuntimeError> {
    let mut sim = SimpleSim::default();
    sim.node_require_join("192.168.2.101", || async move {
        let sock = UdpSocket::bind("0.0.0.0:80").await?;
        sock.connect("192.168.2.102:102").await?;

        sock.try_send(&[1, 2, 3])?;
        sock.try_send(&[4, 5, 6])?;
        // ^ TODO: this should block, but udp send packet does not check interface state

        let err = sock.try_recv_buf(&mut BytesMut::new()).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::WouldBlock);
        Ok(())
    });

    sim.run()
}

#[test]
#[serial]
fn connect_failure() -> Result<(), RuntimeError> {
    let mut sim = SimpleSim::default();
    sim.node_require_join("192.168.2.101", || async move {
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        let error = socket.connect("[2003:1:a::a]:80").await.unwrap_err();
        assert_eq!(
            error.to_string(),
            "address not available - ip version missmatch"
        );
        Ok(())
    });
    sim.run()
}

#[test]
#[serial]
fn connect_no_addrs() -> Result<(), RuntimeError> {
    let mut sim = SimpleSim::default();
    sim.node_require_join("192.168.2.101", || async move {
        let set: &[SocketAddr] = &[];
        let error = UdpSocket::bind("0.0.0.0:0")
            .await?
            .connect(set)
            .await
            .unwrap_err();
        assert_eq!(error.to_string(), "could not resolve to any address");
        Ok(())
    });
    sim.run()
}
