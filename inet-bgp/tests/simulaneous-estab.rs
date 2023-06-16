use std::{
    collections::hash_map::DefaultHasher,
    hash::{Hash, Hasher},
    io::Error,
    net::Ipv4Addr,
    time::Duration,
};

use des::{
    net::{AsyncBuilder, NodeCfg},
    prelude::ChannelMetrics,
    runtime::{random, Builder},
    time::sleep,
};
use inet::{
    interface::{add_interface, Interface, InterfaceName, NetworkDevice},
    TcpListener,
};
use inet_bgp::{
    peering::{BgpPeeringCfg, NeighborDeamon},
    BgpNodeInformation, NeighborEgressEvent, NeighborIngressEvent,
};
use tokio::sync::mpsc::channel;

#[test]
#[serial_test::serial]
fn simulatneous_estab() {
    inet::init();

    // des::tracing::Subscriber::default()
    //     .with_max_level(tracing::metadata::LevelFilter::TRACE)
    //     .init()
    //     .unwrap();

    for seed in 0..100 {
        let mut sim = AsyncBuilder::new();
        sim.set_default_cfg(NodeCfg { join: true });
        sim.node("as-1000", |_| async move {
            let addr = Ipv4Addr::new(192, 168, 1, 100);
            add_interface(Interface::ethv4(NetworkDevice::eth(), addr))?;

            let (etx, erx) = channel(8);
            let (itx, mut irx) = channel(8);
            let (ttx, trx) = channel(8);

            let deamon = NeighborDeamon::new(
                BgpNodeInformation {
                    addr,
                    as_num: 1000,
                    iface: InterfaceName::from("en0"),
                },
                BgpNodeInformation {
                    addr: Ipv4Addr::new(192, 168, 1, 200),
                    as_num: 2000,
                    iface: InterfaceName::from("en0"),
                },
                itx,
                erx,
                trx,
                BgpPeeringCfg::default(),
            );
            tokio::spawn(deamon.deploy());
            tokio::spawn(async move {
                let lis = TcpListener::bind("0.0.0.0:179").await?;
                while let Ok((s, f)) = lis.accept().await {
                    tracing::info!("incoming connection from {}", f);
                    ttx.send(s).await.expect("failed to send")
                }
                Ok::<_, Error>(())
            });

            sleep(Duration::from_secs_f64(random::<f64>() * 0.25)).await;

            etx.send(NeighborEgressEvent::Start)
                .await
                .expect("Failed to send");

            let next = irx.recv().await;
            assert_eq!(
                next,
                Some(NeighborIngressEvent::ConnectionEstablished(
                    BgpNodeInformation {
                        addr: Ipv4Addr::new(192, 168, 1, 200),
                        as_num: 2000,
                        iface: InterfaceName::from("en0"),
                    }
                ))
            );

            Ok(())
        });

        sim.node("as-2000", |_| async move {
            let addr = Ipv4Addr::new(192, 168, 1, 200);
            add_interface(Interface::ethv4(NetworkDevice::eth(), addr))?;

            let (etx, erx) = channel(8);
            let (itx, mut irx) = channel(8);
            let (ttx, trx) = channel(8);

            let deamon = NeighborDeamon::new(
                BgpNodeInformation {
                    addr,
                    as_num: 2000,
                    iface: InterfaceName::from("en0"),
                },
                BgpNodeInformation {
                    addr: Ipv4Addr::new(192, 168, 1, 100),
                    as_num: 1000,
                    iface: InterfaceName::from("en0"),
                },
                itx,
                erx,
                trx,
                BgpPeeringCfg::default(),
            );

            tokio::spawn(deamon.deploy());
            tokio::spawn(async move {
                let lis = TcpListener::bind("0.0.0.0:179").await?;
                while let Ok((s, f)) = lis.accept().await {
                    tracing::info!("incoming connection from {}", f);
                    ttx.send(s).await.expect("failed to send")
                }
                Ok::<_, Error>(())
            });

            sleep(Duration::from_secs_f64(random::<f64>() * 0.25)).await;

            etx.send(NeighborEgressEvent::Start)
                .await
                .expect("Failed to send");

            let next = irx.recv().await;
            assert_eq!(
                next,
                Some(NeighborIngressEvent::ConnectionEstablished(
                    BgpNodeInformation {
                        addr: Ipv4Addr::new(192, 168, 1, 100),
                        as_num: 1000,
                        iface: InterfaceName::from("en0"),
                    }
                ))
            );

            Ok(())
        });

        sim.connect_with(
            "as-1000",
            "as-2000",
            Some(ChannelMetrics {
                bitrate: 1000000,
                latency: Duration::from_millis(5),
                jitter: Duration::ZERO,
                cost: 1.0,
                queuesize: 0,
            }),
        );

        let mut hasher = DefaultHasher::new();
        seed.hash(&mut hasher);

        let _ = Builder::seeded(hasher.finish())
            .max_time(500.0.into())
            .max_itr(10)
            .build(sim.build())
            .run();
    }
}

#[test]
#[serial_test::serial]
fn synced_estab() {
    inet::init();

    // des::tracing::Subscriber::default()
    //     .with_max_level(tracing::metadata::LevelFilter::TRACE)
    //     .init()
    //     .unwrap();

    for seed in 0..10 {
        let mut sim = AsyncBuilder::new();
        sim.set_default_cfg(NodeCfg { join: true });
        sim.node("as-1000", |_| async move {
            let addr = Ipv4Addr::new(192, 168, 1, 100);
            add_interface(Interface::ethv4(NetworkDevice::eth(), addr))?;

            let (etx, erx) = channel(8);
            let (itx, mut irx) = channel(8);
            let (ttx, trx) = channel(8);

            let deamon = NeighborDeamon::new(
                BgpNodeInformation {
                    addr,
                    as_num: 1000,
                    iface: InterfaceName::from("en0"),
                },
                BgpNodeInformation {
                    addr: Ipv4Addr::new(192, 168, 1, 200),
                    as_num: 2000,
                    iface: InterfaceName::from("en0"),
                },
                itx,
                erx,
                trx,
                BgpPeeringCfg::default(),
            );
            tokio::spawn(deamon.deploy());
            tokio::spawn(async move {
                let lis = TcpListener::bind("0.0.0.0:179").await?;
                while let Ok((s, f)) = lis.accept().await {
                    tracing::info!("incoming connection from {}", f);
                    ttx.send(s).await.expect("failed to send")
                }
                Ok::<_, Error>(())
            });

            etx.send(NeighborEgressEvent::Start)
                .await
                .expect("Failed to send");

            let next = irx.recv().await;
            assert_eq!(
                next,
                Some(NeighborIngressEvent::ConnectionEstablished(
                    BgpNodeInformation {
                        addr: Ipv4Addr::new(192, 168, 1, 200),
                        as_num: 2000,
                        iface: InterfaceName::from("en0"),
                    }
                ))
            );

            Ok(())
        });

        sim.node("as-2000", |_| async move {
            let addr = Ipv4Addr::new(192, 168, 1, 200);
            add_interface(Interface::ethv4(NetworkDevice::eth(), addr))?;

            let (etx, erx) = channel(8);
            let (itx, mut irx) = channel(8);
            let (ttx, trx) = channel(8);

            let deamon = NeighborDeamon::new(
                BgpNodeInformation {
                    addr,
                    as_num: 2000,
                    iface: InterfaceName::from("en0"),
                },
                BgpNodeInformation {
                    addr: Ipv4Addr::new(192, 168, 1, 100),
                    as_num: 1000,
                    iface: InterfaceName::from("en0"),
                },
                itx,
                erx,
                trx,
                BgpPeeringCfg::default(),
            );

            tokio::spawn(deamon.deploy());
            tokio::spawn(async move {
                let lis = TcpListener::bind("0.0.0.0:179").await?;
                while let Ok((s, f)) = lis.accept().await {
                    tracing::info!("incoming connection from {}", f);
                    ttx.send(s).await.expect("failed to send")
                }
                Ok::<_, Error>(())
            });

            etx.send(NeighborEgressEvent::Start)
                .await
                .expect("Failed to send");

            let next = irx.recv().await;
            assert_eq!(
                next,
                Some(NeighborIngressEvent::ConnectionEstablished(
                    BgpNodeInformation {
                        addr: Ipv4Addr::new(192, 168, 1, 100),
                        as_num: 1000,
                        iface: InterfaceName::from("en0"),
                    }
                ))
            );

            Ok(())
        });

        sim.connect_with(
            "as-1000",
            "as-2000",
            Some(ChannelMetrics {
                bitrate: 1000000,
                latency: Duration::from_millis(5),
                jitter: Duration::ZERO,
                cost: 1.0,
                queuesize: 0,
            }),
        );

        let mut hasher = DefaultHasher::new();
        seed.hash(&mut hasher);

        let _ = Builder::seeded(hasher.finish())
            .max_time(500.0.into())
            .max_itr(10)
            .build(sim.build())
            .run();
    }
}
