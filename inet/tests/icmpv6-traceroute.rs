use std::{io, net::Ipv6Addr, time::Duration};

use des::{
    net::{Sim, handlers::AsyncHandler},
    prelude::{ChannelDropBehaviour, DatarateChannel, DatarateChannelMetrics, Message, current},
    runtime::Builder,
    time::sleep_until,
};
use inet::{
    env::RoutingInformation,
    interface::{InterfaceDef, NetworkDevice},
    ioctx,
    ipv6::{
        api::{ipv6, set_node_cfg},
        cfg::HostConfiguration,
        router,
        util::traceroute::Trace,
    },
};
use serial_test::serial;
use tokio::sync::mpsc::Receiver;
use types::ip::{Ipv6AddrExt, Ipv6Prefix};

async fn router(_: Receiver<Message>) -> io::Result<()> {
    router::declare_router()?;

    if current().prop::<bool>("noicmp")?.get().is_some() {
        set_node_cfg(HostConfiguration {
            icmp_send_time_exceeded: false,
            ..Default::default()
        })?;
    }

    let ports = RoutingInformation::collect();

    if let Some(lan) = ports.port_by_name("lan") {
        let prefix: Ipv6Prefix = current().prop("lan")?.get().unwrap();
        router::add_routing_interface(
            "lan",
            NetworkDevice::from(lan),
            &[
                Ipv6Addr::from(u128::from(prefix.addr()) + 1),
                Ipv6Addr::LINK_LOCAL,
            ],
            true,
        )?;
        router::add_routing_prefix("lan", prefix)?;
    }

    if let Some(fwd) = ports.port_by_name("fwd") {
        let prefix: Ipv6Prefix = current().prop("fwd")?.get().unwrap();
        router::add_routing_interface(
            "fwd",
            NetworkDevice::from(fwd),
            &[
                Ipv6Addr::from(u128::from(prefix.addr()) + 1),
                Ipv6Addr::LINK_LOCAL,
            ],
            true,
        )?;
        router::add_routing_prefix("fwd", prefix)?;

        router::add_routing_entry(
            "2003:b:1::/64".parse().unwrap(),
            Ipv6Addr::from(u128::from(prefix.addr()) + 2),
            Ipv6Addr::from(u128::from(prefix.addr()) + 1), // < local addr
        )?;
    }

    if let Some(bwd) = ports.port_by_name("bwd") {
        let prefix: Ipv6Prefix = current().prop("bwd")?.get().unwrap();
        router::add_routing_interface(
            "bwd",
            NetworkDevice::from(bwd),
            &[
                Ipv6Addr::from(u128::from(prefix.addr()) + 2),
                Ipv6Addr::LINK_LOCAL,
            ],
            true,
        )?;
        router::add_routing_prefix("bwd", prefix)?;

        router::add_routing_entry(
            "2003:a:1::/64".parse().unwrap(),
            Ipv6Addr::from(u128::from(prefix.addr()) + 1),
            Ipv6Addr::from(u128::from(prefix.addr()) + 2),
        )?;
    }

    Ok(())
}

async fn client(_: Receiver<Message>) -> io::Result<()> {
    let mut handle = ioctx().add_interface(InterfaceDef::ethv6_autocfg(NetworkDevice::eth()))?;
    handle.wait_for_global().await;
    sleep_until(5.0.into()).await;

    let tr = inet::ipv6::util::traceroute::traceroute("2003:b:1::abcd".parse().unwrap()).await?;
    tracing::info!("\n{tr:#?}");

    assert!(matches!(tr.nodes[0], Trace::Found { .. }));
    assert!(matches!(tr.nodes[1], Trace::Found { .. }));
    assert!(matches!(tr.nodes[2], Trace::Found { .. }));
    assert!(matches!(tr.nodes[3], Trace::NotFound));
    assert!(matches!(tr.nodes[4], Trace::Found { .. }));

    ipv6();

    Ok(())
}

async fn server(_: Receiver<Message>) -> io::Result<()> {
    let handle = ioctx().add_interface(InterfaceDef::ethv6_autocfg(NetworkDevice::eth()))?;
    handle.add_addr("2003:b:1::abcd".parse().unwrap())?;
    Ok(())
}

fn lan() -> Option<DatarateChannel> {
    Some(DatarateChannel::new(DatarateChannelMetrics::new(
        8_000_000,
        Duration::from_millis(5),
        Duration::ZERO,
        ChannelDropBehaviour::Queue(None),
    )))
}

const CFG: &str = "
src-router.lan: 2003:a:1::/64
src-router.fwd: 2004:a:1::/64
router-a.bwd: 2004:a:1::/64
router-a.fwd: 2004:b:1::/64
router-b.bwd: 2004:b:1::/64
router-b.fwd: 2004:c:1::/64
router-c.bwd: 2004:c:1::/64
router-c.fwd: 2004:d:1::/64
router-c.noicmp: true
dst-router.bwd: 2004:d:1::/64
dst-router.lan: 2003:b:1::/64
";

#[test]
#[serial]
fn run() -> Result<(), des::net::Failure> {
    des::tracing::init();

    let mut sim = Sim::new(()).with_stack(inet::init);
    sim.include_cfg(CFG);

    sim.node("client", AsyncHandler::io(client).require_join());
    sim.node("src-router", AsyncHandler::io(router).require_join());
    sim.node("router-a", AsyncHandler::io(router).require_join());
    sim.node("router-b", AsyncHandler::io(router).require_join());
    sim.node("router-c", AsyncHandler::io(router).require_join());
    sim.node("dst-router", AsyncHandler::io(router).require_join());
    sim.node("server", AsyncHandler::io(server).require_join());

    // LAN connections
    sim.gate("client", "port")
        .connect_with(sim.gate("src-router", "lan"), lan());
    sim.gate("server", "port")
        .connect_with(sim.gate("dst-router", "lan"), lan());

    // Router path connections
    sim.gate("src-router", "fwd")
        .connect_with(sim.gate("router-a", "bwd"), lan());
    sim.gate("router-a", "fwd")
        .connect_with(sim.gate("router-b", "bwd"), lan());
    sim.gate("router-b", "fwd")
        .connect_with(sim.gate("router-c", "bwd"), lan());
    sim.gate("router-c", "fwd")
        .connect_with(sim.gate("dst-router", "bwd"), lan());

    Builder::seeded(123)
        .max_time(100.0.into())
        .build(sim.freeze())
        .run()
        .as_result()
        .map(|_| ())
}
