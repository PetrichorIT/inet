use des::{net::handlers::AsyncHandler, prelude::*, time::sleep};
use serial_test::serial;

use crate::{
    UdpSocket,
    interface::{InterfaceDef, NetworkDevice},
    ioctx,
    utils::SimpleSim,
};

const CHANNEL: DatarateChannelMetrics = DatarateChannelMetrics::new(
    8_000_000,
    Duration::from_millis(20),
    Duration::ZERO,
    ChannelDropBehaviour::Queue(None),
);

#[test]
#[serial]
fn specific_bind_recv_restrictivly() -> Result<(), RuntimeError> {
    let mut sim = Sim::new(()).with_stack(crate::init);
    sim.node(
        "receiver",
        AsyncHandler::io(|_| async move {
            ioctx().add_interface(
                InterfaceDef::new("net-a", NetworkDevice::gate("net-a", 0).unwrap())
                    .ip(Ipv4Addr::new(192, 168, 2, 100).into()),
            )?;
            ioctx().add_interface(
                InterfaceDef::new("net-b", NetworkDevice::gate("net-b", 0).unwrap())
                    .ip(Ipv4Addr::new(10, 20, 30, 100).into()),
            )?;

            // ignore packet from 10.20.30.101
            let udp = UdpSocket::bind("192.168.2.100:100").await?;
            let mut buf = [0; 100];
            let (_, from) = udp.recv_from(&mut buf).await?;
            assert_eq!(from.ip(), Ipv4Addr::new(192, 168, 2, 101));

            Ok(())
        }),
    );

    sim.node(
        "net-a-sender",
        AsyncHandler::io(|_| async move {
            ioctx().add_interface(
                InterfaceDef::new("en0", NetworkDevice::eth())
                    .ip(Ipv4Addr::new(192, 168, 2, 101).into()),
            )?;

            // This is the correct packet, send it later
            sleep(Duration::from_secs(5)).await;

            UdpSocket::bind("0.0.0.0:0")
                .await?
                .send_to(&[1, 2, 3], "192.168.2.100:100")
                .await?;

            Ok(())
        }),
    );

    sim.node(
        "net-b-sender",
        AsyncHandler::io(|_| async move {
            ioctx().add_interface(
                InterfaceDef::new("en0", NetworkDevice::eth())
                    .ip(Ipv4Addr::new(10, 20, 30, 101).into()),
            )?;

            UdpSocket::bind("0.0.0.0:0")
                .await?
                .send_to(&[1, 2, 3], "10.20.30.100:100")
                .await?;

            Ok(())
        }),
    );

    sim.gate("net-a-sender", "port").connect_with(
        sim.gate("receiver", "net-a"),
        Some(DatarateChannel::new(CHANNEL)),
    );
    sim.gate("net-b-sender", "port").connect_with(
        sim.gate("receiver", "net-b"),
        Some(DatarateChannel::new(CHANNEL)),
    );

    Builder::seeded(132)
        .max_time(100.0.into())
        .build(sim.freeze())
        .run()
        .map(|_| ())
}

#[test]
#[serial]
fn zero_bind_recv_all() -> Result<(), RuntimeError> {
    let mut sim = Sim::new(()).with_stack(crate::init);
    sim.node(
        "receiver",
        AsyncHandler::io(|_| async move {
            ioctx().add_interface(
                InterfaceDef::new("net-a", NetworkDevice::gate("net-a", 0).unwrap())
                    .ip(Ipv4Addr::new(192, 168, 2, 100).into()),
            )?;
            ioctx().add_interface(
                InterfaceDef::new("net-b", NetworkDevice::gate("net-b", 0).unwrap())
                    .ip(Ipv4Addr::new(10, 20, 30, 100).into()),
            )?;

            let udp = UdpSocket::bind("0.0.0.0:100").await?;
            let mut buf = [0; 100];
            let (_, from) = udp.recv_from(&mut buf).await?;
            assert_eq!(from.ip(), Ipv4Addr::new(10, 20, 30, 101));

            let (_, from) = udp.recv_from(&mut buf).await?;
            assert_eq!(from.ip(), Ipv4Addr::new(192, 168, 2, 101));

            Ok(())
        }),
    );

    sim.node(
        "net-a-sender",
        AsyncHandler::io(|_| async move {
            ioctx().add_interface(
                InterfaceDef::new("en0", NetworkDevice::eth())
                    .ip(Ipv4Addr::new(192, 168, 2, 101).into()),
            )?;

            sleep(Duration::from_secs(5)).await;

            UdpSocket::bind("0.0.0.0:0")
                .await?
                .send_to(&[1, 2, 3], "192.168.2.100:100")
                .await?;

            Ok(())
        }),
    );

    sim.node(
        "net-b-sender",
        AsyncHandler::io(|_| async move {
            ioctx().add_interface(
                InterfaceDef::new("en0", NetworkDevice::eth())
                    .ip(Ipv4Addr::new(10, 20, 30, 101).into()),
            )?;

            UdpSocket::bind("0.0.0.0:0")
                .await?
                .send_to(&[1, 2, 3], "10.20.30.100:100")
                .await?;

            Ok(())
        }),
    );

    sim.gate("net-a-sender", "port").connect_with(
        sim.gate("receiver", "net-a"),
        Some(DatarateChannel::new(CHANNEL)),
    );
    sim.gate("net-b-sender", "port").connect_with(
        sim.gate("receiver", "net-b"),
        Some(DatarateChannel::new(CHANNEL)),
    );

    Builder::seeded(132)
        .max_time(100.0.into())
        .build(sim.freeze())
        .run()
        .map(|_| ())
}

#[test]
#[serial]
fn bind_no_addrs() -> Result<(), RuntimeError> {
    let mut sim = SimpleSim::default();
    sim.node_require_join("192.168.2.101", || async move {
        let set: &[SocketAddr] = &[];
        let error = UdpSocket::bind(set).await.unwrap_err();
        assert_eq!(error.to_string(), "could not resolve to any address");
        Ok(())
    });
    sim.run()
}
