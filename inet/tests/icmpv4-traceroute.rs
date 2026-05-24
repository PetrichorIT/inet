use std::{io, net::Ipv4Addr, time::Duration};

use des::{
    Sim,
    gate::IntoGate,
    prelude::{ChannelDropBehaviour, DatarateChannel, DatarateChannelMetrics, Message, current},
    runtime::handlers::AsyncHandler,
    time::sleep_until,
};
use inet::{
    env::RoutingInformation,
    interface::{DEFAULT_V4_MASK, InterfaceDef, NetworkDevice},
    ioctx,
    ipv4::{
        HostConfiguration,
        router::{self, set_default_gateway},
        set_host_config,
        util::traceroute::{Trace, traceroute},
    },
};
use serial_test::serial;
use tokio::sync::mpsc::Receiver;
use types::ip::Ipv4Prefix;

async fn router(_: Receiver<Message>) -> io::Result<()> {
    if current().prop::<bool>("noicmp")?.get().is_some() {
        set_host_config(HostConfiguration {
            no_icmp_responses: true,
            ..Default::default()
        })?;
    }

    let ports = RoutingInformation::collect();

    if let Some(lan) = ports.port_by_name("lan") {
        let prefix: Ipv4Prefix = current().prop("lan")?.get().unwrap();
        ioctx().add_interface(
            InterfaceDef::new("lan", NetworkDevice::from(lan))
                .ipv4(Ipv4Addr::from(u32::from(prefix.addr()) + 1)),
        )?;
    }

    if let Some(fwd) = ports.port_by_name("fwd") {
        let prefix: Ipv4Prefix = current().prop("fwd")?.get().unwrap();
        ioctx().add_interface(
            InterfaceDef::new("fwd", NetworkDevice::from(fwd))
                .ipv4(Ipv4Addr::from(u32::from(prefix.addr()) + 1)),
        )?;

        router::add_routing_entry(
            "100.6.6.0".parse().unwrap(),
            DEFAULT_V4_MASK,
            Ipv4Addr::from(u32::from(prefix.addr()) + 2), // < local addr
            "fwd",
        )?;
    }

    if let Some(bwd) = ports.port_by_name("bwd") {
        let prefix: Ipv4Prefix = current().prop("bwd")?.get().unwrap();
        ioctx().add_interface(
            InterfaceDef::new("bwd", NetworkDevice::from(bwd))
                .ipv4(Ipv4Addr::from(u32::from(prefix.addr()) + 2)),
        )?;

        router::add_routing_entry(
            "100.1.1.0".parse().unwrap(),
            DEFAULT_V4_MASK,
            Ipv4Addr::from(u32::from(prefix.addr()) + 1), // < local addr
            "bwd",
        )?;
    }

    Ok(())
}

const CLIENT: Ipv4Addr = Ipv4Addr::new(100, 1, 1, 50);

async fn client(_: Receiver<Message>) -> io::Result<()> {
    ioctx().add_interface(InterfaceDef::new("en0", NetworkDevice::eth()).ip(CLIENT.into()))?;
    set_default_gateway("100.1.1.1".parse().unwrap())?;
    sleep_until(5.0.into()).await;

    let tr = traceroute(TARGET).await?;
    tracing::info!("\n{tr:#?}");

    assert!(matches!(tr.nodes[0], Trace::Found { .. }));
    assert!(matches!(tr.nodes[1], Trace::Found { .. }));
    assert!(matches!(tr.nodes[2], Trace::Found { .. }));
    assert!(matches!(tr.nodes[3], Trace::NotFound));
    assert!(matches!(tr.nodes[4], Trace::Found { .. }));

    Ok(())
}

const TARGET: Ipv4Addr = Ipv4Addr::new(100, 6, 6, 50);

async fn server(_: Receiver<Message>) -> io::Result<()> {
    ioctx().add_interface(InterfaceDef::new("en0", NetworkDevice::eth()).ip(TARGET.into()))?;
    set_default_gateway("100.6.6.1".parse().unwrap())?;

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
src-router.lan: 100.1.1.0/24
src-router.fwd: 100.2.2.0/24
router-a.bwd: 100.2.2.0/24
router-a.fwd: 100.3.3.0/24
router-b.bwd: 100.3.3.0/24
router-b.fwd: 100.4.4.0/24
router-c.bwd: 100.4.4.0/24
router-c.fwd: 100.5.5.0/24
router-c.noicmp: true
dst-router.bwd: 100.5.5.0/24
dst-router.lan: 100.6.6.0/24
";

#[test]
#[serial]
fn run() -> Result<(), des::Failure> {
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

    sim.seeded(123)
        .max_time(100.0.into())
        .build()
        .run()
        .into_result()
        .map(|_| ())
}
