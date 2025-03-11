use std::{
    collections::HashMap,
    io,
    net::{Ipv4Addr, Ipv6Addr},
    str::FromStr,
    time::Duration,
};

use des::{
    runtime::{random, RuntimeError},
    time::sleep,
};
use serial_test::serial;

use crate::{test_util::SimpleSim, UdpSocket};

#[test]
#[serial]
fn ipv4() -> Result<(), RuntimeError> {
    let mut sim = SimpleSim::new(crate::init);

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
    let mut sim = SimpleSim::new(crate::init);

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
