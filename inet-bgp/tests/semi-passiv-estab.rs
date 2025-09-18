use std::{io::Error, net::Ipv4Addr, time::Duration};

use des::{
    net::{channel::DatarateChannel, handlers::AsyncHandler, Sim},
    prelude::DatarateChannelMetrics,
    runtime::Builder,
    time::sleep,
};
use inet::{
    interface::{add_interface, InterfaceDef, InterfaceName, NetworkDevice},
    tcp2::TcpListener,
};
use inet_bgp::{
    peering::{BgpPeeringCfg, NeighborDeamon},
    BgpNodeInformation, NeighborEgressEvent, NeighborIngressEvent,
};
use tokio::sync::mpsc::channel;

#[test]
#[serial_test::serial]
fn semi_passiv_estab() {
    let mut sim = Sim::new(()).with_stack(inet::init);
    sim.node(
        "as-1000",
        AsyncHandler::io(|_| async move {
            let addr = Ipv4Addr::new(192, 168, 1, 100);
            add_interface(InterfaceDef::new("en0", NetworkDevice::eth()).ip(addr.into()))?;

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
        })
        .require_join(),
    );

    sim.node(
        "as-2000",
        AsyncHandler::io(|_| async move {
            let addr = Ipv4Addr::new(192, 168, 1, 200);
            add_interface(InterfaceDef::new("en0", NetworkDevice::eth()).ip(addr.into()))?;

            let (etx, erx) = channel(8);
            let (itx, mut irx) = channel(8);
            let (ttx, trx) = channel(8);

            let mut deamon = NeighborDeamon::new(
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
            deamon.cfg.passiv_tcp_estab = true;

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
        })
        .require_join(),
    );

    let tx = sim.gate("as-1000", "port");
    let rx = sim.gate("as-2000", "port");
    tx.connect_with(
        rx,
        Some(DatarateChannel::new(DatarateChannelMetrics {
            bitrate: 1000000,
            latency: Duration::from_millis(5),
            jitter: Duration::ZERO,
            drop_behaviour: Default::default(),
        })),
    );

    let _ = Builder::seeded(123)
        .max_time(500.0.into())
        .max_itr(10_000)
        .build(sim.freeze())
        .run();
}

#[test]
#[serial_test::serial]
fn semi_passiv_estab_delayed_client() {
    let mut sim = Sim::new(()).with_stack(inet::init);
    sim.node(
        "as-1000",
        AsyncHandler::io(|_| async move {
            let addr = Ipv4Addr::new(192, 168, 1, 100);
            add_interface(InterfaceDef::new("en0", NetworkDevice::eth()).ip(addr.into()))?;

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

            sleep(Duration::from_secs(10)).await;

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
        })
        .require_join(),
    );

    sim.node(
        "as-2000",
        AsyncHandler::io(|_| async move {
            let addr = Ipv4Addr::new(192, 168, 1, 200);
            add_interface(InterfaceDef::new("en0", NetworkDevice::eth()).ip(addr.into()))?;

            let (etx, erx) = channel(8);
            let (itx, mut irx) = channel(8);
            let (ttx, trx) = channel(8);

            let mut deamon = NeighborDeamon::new(
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
            deamon.cfg.passiv_tcp_estab = true;

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
        })
        .require_join(),
    );

    let tx = sim.gate("as-1000", "port");
    let rx = sim.gate("as-2000", "port");
    tx.connect_with(
        rx,
        Some(DatarateChannel::new(DatarateChannelMetrics {
            bitrate: 1000000,
            latency: Duration::from_millis(5),
            jitter: Duration::ZERO,
            drop_behaviour: Default::default(),
        })),
    );

    let _ = Builder::seeded(123)
        .max_time(500.0.into())
        .max_itr(10_000)
        .build(sim.freeze())
        .run();
}

#[test]
#[serial_test::serial]
fn semi_passiv_estab_delayed_open() {
    let mut sim = Sim::new(()).with_stack(inet::init);
    sim.node(
        "as-1000",
        AsyncHandler::io(|_| async move {
            let addr = Ipv4Addr::new(192, 168, 1, 100);
            add_interface(InterfaceDef::new("en0", NetworkDevice::eth()).ip(addr.into()))?;

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

            sleep(Duration::from_secs(10)).await;

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
        })
        .require_join(),
    );

    sim.node(
        "as-2000",
        AsyncHandler::io(|_| async move {
            let addr = Ipv4Addr::new(192, 168, 1, 200);
            add_interface(InterfaceDef::new("en0", NetworkDevice::eth()).ip(addr.into()))?;

            let (etx, erx) = channel(8);
            let (itx, mut irx) = channel(8);
            let (ttx, trx) = channel(8);

            let mut deamon = NeighborDeamon::new(
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
            deamon.cfg.passiv_tcp_estab = true;
            deamon.cfg.delay_open = true;

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
        })
        .require_join(),
    );

    let tx = sim.gate("as-1000", "port");
    let rx = sim.gate("as-2000", "port");
    tx.connect_with(
        rx,
        Some(DatarateChannel::new(DatarateChannelMetrics {
            bitrate: 1000000,
            latency: Duration::from_millis(5),
            jitter: Duration::ZERO,
            drop_behaviour: Default::default(),
        })),
    );

    let _ = Builder::seeded(123)
        .max_time(500.0.into())
        .max_itr(10_000)
        .build(sim.freeze())
        .run();
}
