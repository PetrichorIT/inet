use std::{io, iter::repeat_with, str::FromStr};

use bytes_io::BytesMut;
use des::{
    net::{globals, AsyncFn},
    prelude::*,
    runtime::rng,
    time::sleep,
};
use inet::{
    interface::{add_interface, InterfaceDef, NetworkDevice},
    ipv6::router,
    utils::LinkLayerSwitch,
    UdpSocket,
};
use rand::seq::IndexedRandom;
use types::ip::{Ipv6AddrExt, Ipv6AddrScope};

const LAN: ChannelMetrics = ChannelMetrics::new(
    80_000_000,
    Duration::from_millis(5),
    Duration::ZERO,
    ChannelDropBehaviour::Queue(None),
);

const WAN: ChannelMetrics = ChannelMetrics::new(
    8_000_000,
    Duration::from_millis(15),
    Duration::ZERO,
    ChannelDropBehaviour::Queue(None),
);

/// Network graph:
///
/// H1 --+
///       \
/// H2 --- S1 --- R1
///       /       |
/// H3 --+        R2
///               |
/// H4 --- S2 --- S3
///       /      /
/// H5 --+      /
///            /
/// H6 -------+
///
#[test]
fn run() -> Result<(), RuntimeError> {
    des::tracing::init();

    let mut sim = Sim::new(()).with_stack(inet::init);

    sim.node("switch-1", LinkLayerSwitch::default());
    sim.node("switch-2", LinkLayerSwitch::default());
    sim.node("switch-3", LinkLayerSwitch::default());

    sim.node(
        "router-1",
        AsyncFn::io(|_| async move {
            router::declare_router()?;
            router::add_routing_prefix("2003:a:1::/64".parse()?)?;
            router::add_routing_prefix("2003:a:2::/64".parse()?)?;

            router::add_routing_interface(
                "en-lan",
                NetworkDevice::gate("lan", 0).unwrap(),
                &[
                    "2003:a:1::1".parse().unwrap(),
                    "2003:a:2::1".parse().unwrap(),
                    Ipv6Addr::LINK_LOCAL,
                ],
                true,
            )?;

            router::add_routing_interface(
                "en-wan",
                NetworkDevice::gate("wan", 0).unwrap(),
                &["2003:a::1".parse().unwrap(), Ipv6Addr::LINK_LOCAL],
                true,
            )?;

            router::add_routing_entry(
                "2003:b:1::/64".parse()?,
                "2003:b::1".parse().unwrap(),
                "2003:a::1".parse().unwrap(),
            )?;

            Ok(())
        }),
    );
    sim.node(
        "router-2",
        AsyncFn::io(|_| async move {
            router::declare_router()?;
            router::add_routing_prefix("2003:b:1::/64".parse()?)?;

            router::add_routing_interface(
                "en-lan",
                NetworkDevice::gate("lan", 0).unwrap(),
                &["2003:b:1::1".parse().unwrap(), Ipv6Addr::LINK_LOCAL],
                true,
            )?;

            router::add_routing_interface(
                "en-wan",
                NetworkDevice::gate("wan", 0).unwrap(),
                &["2003:b::1".parse().unwrap(), Ipv6Addr::LINK_LOCAL],
                true,
            )?;

            router::add_routing_entry(
                "2003:a:1::/64".parse()?,
                "2003:a::1".parse().unwrap(),
                "2003:b::1".parse().unwrap(),
            )?;

            router::add_routing_entry(
                "2003:a:2::/64".parse()?,
                "2003:a::1".parse().unwrap(),
                "2003:b::1".parse().unwrap(),
            )?;

            Ok(())
        }),
    );

    sim.node(
        "host-1",
        AsyncFn::io(|_| async move {
            add_interface(InterfaceDef::ethv6_autocfg(NetworkDevice::eth()))?;
            tokio::spawn(pong(800));

            sleep(Duration::from_secs(5)).await;
            let available = ["host-1", "host-2", "host-3", "host-4"];
            for _ in 0..100 {
                let addr = pick_target_addr(&available);
                ping(addr, 800).await?;
            }

            Ok(())
        }),
    );
    sim.node(
        "host-2",
        AsyncFn::io(|_| async move {
            add_interface(InterfaceDef::ethv6_autocfg(NetworkDevice::eth()))?;
            tokio::spawn(pong(800));

            sleep(Duration::from_secs(5)).await;
            let available = ["host-6", "host-2", "host-1", "host-4"];
            for _ in 0..100 {
                let addr = pick_target_addr(&available);
                ping(addr, 800).await?;
            }

            Ok(())
        }),
    );
    sim.node(
        "host-3",
        AsyncFn::io(|_| async move {
            add_interface(InterfaceDef::ethv6_autocfg(NetworkDevice::eth()))?;
            tokio::spawn(pong(800));

            sleep(Duration::from_secs(5)).await;
            let available = ["host-1", "host-2", "host-3", "host-4"];
            for _ in 0..100 {
                let addr = pick_target_addr(&available);
                ping(addr, 800).await?;
            }

            Ok(())
        }),
    );
    sim.node(
        "host-4",
        AsyncFn::io(|_| async move {
            add_interface(InterfaceDef::ethv6_autocfg(NetworkDevice::eth()))?;
            tokio::spawn(pong(800));

            sleep(Duration::from_secs(5)).await;
            let available = ["host-1", "host-2", "host-3", "host-4"];
            for _ in 0..100 {
                let addr = pick_target_addr(&available);
                ping(addr, 800).await?;
            }

            Ok(())
        }),
    );
    sim.node(
        "host-5",
        AsyncFn::io(|_| async move {
            add_interface(InterfaceDef::ethv6_autocfg(NetworkDevice::eth()))?;
            tokio::spawn(pong(800));

            sleep(Duration::from_secs(5)).await;
            let available = ["host-6", "host-2", "host-3", "host-4"];
            for _ in 0..100 {
                let addr = pick_target_addr(&available);
                ping(addr, 800).await?;
            }

            Ok(())
        }),
    );
    sim.node(
        "host-6",
        AsyncFn::io(|_| async move {
            add_interface(InterfaceDef::ethv6_autocfg(NetworkDevice::eth()))?;
            tokio::spawn(pong(800));

            sleep(Duration::from_secs(5)).await;
            let available = ["host-1", "host-5", "host-3", "host-6"];
            for _ in 0..100 {
                let addr = pick_target_addr(&available);
                ping(addr, 800).await?;
            }

            Ok(())
        }),
    );

    // Connectors
    sim.gate("host-1", "port")
        .connect(sim.gate("switch-1", "port-0"), Some(Channel::new(LAN)));
    sim.gate("host-2", "port")
        .connect(sim.gate("switch-1", "port-1"), Some(Channel::new(LAN)));
    sim.gate("host-3", "port")
        .connect(sim.gate("switch-1", "port-2"), Some(Channel::new(LAN)));
    sim.gate("host-4", "port")
        .connect(sim.gate("switch-2", "port-0"), Some(Channel::new(LAN)));
    sim.gate("host-5", "port")
        .connect(sim.gate("switch-2", "port-1"), Some(Channel::new(LAN)));
    sim.gate("host-6", "port")
        .connect(sim.gate("switch-3", "port-1"), Some(Channel::new(LAN))); // port-0 is switch 2

    // Fabric
    sim.gate("switch-1", "upstream")
        .connect(sim.gate("router-1", "lan"), Some(Channel::new(LAN)));
    sim.gate("router-1", "wan")
        .connect(sim.gate("router-2", "wan"), Some(Channel::new(WAN)));
    sim.gate("router-2", "lan")
        .connect(sim.gate("switch-3", "upstream"), Some(Channel::new(LAN)));
    sim.gate("switch-3", "port-0")
        .connect(sim.gate("switch-2", "upstream"), Some(Channel::new(LAN)));

    let (_, _, _) = Builder::seeded(213)
        .max_time(100.0.into())
        .build(sim)
        .run()?;

    Ok(())
}

fn pick_target_addr(hosts: &[&str]) -> Ipv6Addr {
    let host = hosts.choose(&mut rng()).unwrap();
    let addr = globals()
        .node(*host)
        .expect("node must exists")
        .prop::<Vec<Ipv6Addr>>("inet.addrs.v6")
        .expect("prop failed")
        .get()
        .into_iter()
        .filter(|addr| addr.scope() >= Ipv6AddrScope::UnicastGlobal)
        .next()
        .expect("no valid addr found");

    addr
}

async fn ping(addr: Ipv6Addr, port: u16) -> io::Result<()> {
    let sock = UdpSocket::bind(":::0").await?;
    sock.connect((addr, port)).await?;
    let bytes = repeat_with(|| des::runtime::random::<u8>())
        .take(100)
        .collect::<Vec<_>>();
    sock.send(&bytes).await?;

    let mut buf = BytesMut::with_capacity(1024);
    let _ = sock.recv_buf(&mut buf).await?;
    assert_eq!(buf[..], bytes);

    tracing::info!("ping succeded");

    Ok(())
}

async fn pong(port: u16) -> io::Result<()> {
    let sock = UdpSocket::bind(("::", port)).await?;
    let mut buf = BytesMut::with_capacity(1024);
    loop {
        buf.clear();
        buf.reserve(100);
        let (n, from) = sock.recv_buf_from(&mut buf).await?;
        tracing::info!("received {n} bytes from {from}: {buf:?}");
        sock.send_to(&buf, from).await?;
    }
}

// WAY TOO MANY ACTIVE EVENTS
