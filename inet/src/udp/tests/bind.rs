use des::{net::AsyncFn, prelude::*, time::sleep};
use serial_test::serial;

use crate::{
    interface::{add_interface, Interface, NetworkDevice},
    UdpSocket,
};

const CHANNEL: ChannelMetrics = ChannelMetrics::new(
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
        AsyncFn::io(|_| async move {
            add_interface(
                Interface::ethv4(
                    NetworkDevice::gate("net-a", 0).unwrap(),
                    Ipv4Addr::new(192, 168, 2, 100),
                )
                .named("net-a"),
            )?;
            add_interface(
                Interface::ethv4(
                    NetworkDevice::gate("net-b", 0).unwrap(),
                    Ipv4Addr::new(10, 20, 30, 100),
                )
                .named("net-b"),
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
        AsyncFn::io(|_| async move {
            add_interface(Interface::ethv4(
                NetworkDevice::eth(),
                Ipv4Addr::new(192, 168, 2, 101),
            ))?;

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
        AsyncFn::io(|_| async move {
            add_interface(Interface::ethv4(
                NetworkDevice::eth(),
                Ipv4Addr::new(10, 20, 30, 101),
            ))?;

            UdpSocket::bind("0.0.0.0:0")
                .await?
                .send_to(&[1, 2, 3], "10.20.30.100:100")
                .await?;

            Ok(())
        }),
    );

    sim.gate("net-a-sender", "port")
        .connect(sim.gate("receiver", "net-a"), Some(Channel::new(CHANNEL)));
    sim.gate("net-b-sender", "port")
        .connect(sim.gate("receiver", "net-b"), Some(Channel::new(CHANNEL)));

    Builder::seeded(132)
        .max_time(100.0.into())
        .build(sim)
        .run()
        .map(|_| ())
}

#[test]
#[serial]
fn zero_bind_recv_all() -> Result<(), RuntimeError> {
    let mut sim = Sim::new(()).with_stack(crate::init);
    sim.node(
        "receiver",
        AsyncFn::io(|_| async move {
            add_interface(
                Interface::ethv4(
                    NetworkDevice::gate("net-a", 0).unwrap(),
                    Ipv4Addr::new(192, 168, 2, 100),
                )
                .named("net-a"),
            )?;
            add_interface(
                Interface::ethv4(
                    NetworkDevice::gate("net-b", 0).unwrap(),
                    Ipv4Addr::new(10, 20, 30, 100),
                )
                .named("net-b"),
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
        AsyncFn::io(|_| async move {
            add_interface(Interface::ethv4(
                NetworkDevice::eth(),
                Ipv4Addr::new(192, 168, 2, 101),
            ))?;

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
        AsyncFn::io(|_| async move {
            add_interface(Interface::ethv4(
                NetworkDevice::eth(),
                Ipv4Addr::new(10, 20, 30, 101),
            ))?;

            UdpSocket::bind("0.0.0.0:0")
                .await?
                .send_to(&[1, 2, 3], "10.20.30.100:100")
                .await?;

            Ok(())
        }),
    );

    sim.gate("net-a-sender", "port")
        .connect(sim.gate("receiver", "net-a"), Some(Channel::new(CHANNEL)));
    sim.gate("net-b-sender", "port")
        .connect(sim.gate("receiver", "net-b"), Some(Channel::new(CHANNEL)));

    Builder::seeded(132)
        .max_time(100.0.into())
        .build(sim)
        .run()
        .map(|_| ())
}
