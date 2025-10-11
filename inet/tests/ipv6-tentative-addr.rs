use std::{net::IpAddr, time::Duration};

use bytes_io::FromBytes;
use des::{
    net::{
        Sim,
        channel::{ChannelDropBehaviour, DatarateChannel, DatarateChannelMetrics},
        handlers::AsyncHandler,
        module::Module,
    },
    runtime::{Builder, RuntimeError},
    time::SimTime,
};
use inet::{
    interface::{InterfaceDef, NetworkDevice},
    ioctx,
    ipv6::{api::set_node_cfg, cfg::HostConfiguration, router},
};
use serial_test::serial;
use types::{icmpv6::IcmpV6Packet, iface::MacAddress, ip::Ipv6Packet};

#[derive(Default)]
struct WithChecks;

impl Module for WithChecks {
    fn at_sim_start(&mut self, _stage: usize) {
        let handle = ioctx()
            .add_interface(InterfaceDef::new("en0", NetworkDevice::eth()).v6())
            .unwrap();

        let state = handle.status();
        assert_eq!(state.addrs.addrs().count(), 0);
        assert_eq!(state.addrs.multicast_scopes().len(), 1); // sol-multicast (delayed) + all nodes multicast
    }

    fn at_sim_end(&mut self) -> Result<(), RuntimeError> {
        let state = ioctx().get_interface("en0").unwrap().status();
        assert_eq!(state.addrs.addrs().count(), 1);
        assert_eq!(state.addrs.multicast_scopes().len(), 2); // sol-multicast (delayed) + all nodes multicast
        Ok(())
    }
}

#[derive(Default)]
struct WithoutChecks;

impl Module for WithoutChecks {
    fn at_sim_start(&mut self, _stage: usize) {
        set_node_cfg(HostConfiguration {
            dup_addr_detect_transmits: 0,
            ..Default::default()
        })
        .unwrap();

        let handle = ioctx()
            .add_interface(InterfaceDef::new("en0", NetworkDevice::eth()).v6())
            .unwrap();
        let state = handle.status();
        assert_eq!(state.addrs.addrs().count(), 1);
        assert_eq!(state.addrs.multicast_scopes().len(), 2); // sol-multicast + all nodes multicast
    }

    fn at_sim_end(&mut self) -> Result<(), RuntimeError> {
        let state = ioctx().get_interface("en0").unwrap().status();
        assert_eq!(state.addrs.addrs().count(), 1);
        assert_eq!(state.addrs.multicast_scopes().len(), 2); // sol-multicast + all nodes multicast
        Ok(())
    }
}

#[derive(Default)]
struct ManualAssignWithoutDedup;

impl Module for ManualAssignWithoutDedup {
    fn at_sim_start(&mut self, _stage: usize) {
        let handle = ioctx()
            .add_interface(InterfaceDef::ethv6_autocfg(NetworkDevice::eth()))
            .unwrap();

        let state = handle.status();
        assert_eq!(state.addrs.addrs().count(), 1);
        assert_eq!(state.addrs.multicast_scopes().len(), 2); // sol-multicast + all nodes multicast
    }

    fn at_sim_end(&mut self) -> Result<(), RuntimeError> {
        let state = ioctx().get_interface("en0").unwrap().status();
        assert_eq!(state.addrs.addrs().count(), 1);
        assert_eq!(state.addrs.multicast_scopes().len(), 2); // sol-multicast + all nodes multicast
        Ok(())
    }
}

#[derive(Default)]
struct OnlyRouterSolOrMDL;

impl Module for OnlyRouterSolOrMDL {
    fn handle_message(&mut self, msg: des::prelude::Message) {
        let pkt = msg.body.content::<Ipv6Packet>();
        let icmp = IcmpV6Packet::peek_from(&pkt.content[..]).unwrap();
        assert!(matches!(
            icmp,
            IcmpV6Packet::RouterSolicitation(_) | IcmpV6Packet::MulticastListenerReport(_)
        ));
    }
}

#[derive(Default)]
struct AssignSameAddr;

impl Module for AssignSameAddr {
    fn at_sim_start(&mut self, _: usize) {
        let mut device = NetworkDevice::eth();
        let mac = MacAddress::from([1, 2, 3, 4, 5, 6]);
        assert!(!mac.is_multicast());
        device.addr = mac;
        ioctx()
            .add_interface(InterfaceDef::new("en0", device).v6())
            .unwrap();
    }

    fn at_sim_end(&mut self) -> Result<(), RuntimeError> {
        assert_ne!(
            ioctx()
                .get_interface("en0")
                .unwrap()
                .status()
                .addrs
                .addrs()
                .collect::<Vec<_>>(),
            ["fe80::12:2345".parse::<IpAddr>().unwrap()]
        );
        Ok(())
    }
}

struct Router;
impl Module for Router {
    fn at_sim_start(&mut self, _stage: usize) {
        router::declare_router().unwrap();
        router::add_routing_interface(
            "port",
            NetworkDevice::eth(),
            &["2003:a:1::1".parse().unwrap()],
            true,
        )
        .unwrap();
        router::add_routing_prefix("port", "2003:a:1::/64".parse().unwrap()).unwrap();
    }
}

#[test]
#[serial]
fn tentative_addr_with_checks() -> Result<(), RuntimeError> {
    // des::tracing::init();

    let mut app = Sim::new(()).with_stack(inet::init);
    app.node("a", WithChecks::default());
    app.node("b", WithChecks::default());

    let ag = app.gate("a", "port");
    let bg = app.gate("b", "port");

    let chan = DatarateChannel::new(DatarateChannelMetrics {
        bitrate: 1000000,
        latency: Duration::from_millis(50),
        jitter: Duration::ZERO,
        drop_behaviour: ChannelDropBehaviour::Drop,
    });
    ag.connect_with(bg, Some(chan));

    let rt = Builder::seeded(123).build(app.freeze());
    rt.run().map(|_| ())
}

#[test]
#[serial]
fn tentative_addr_without_checks() -> Result<(), RuntimeError> {
    // des::tracing::init();

    let mut app = Sim::new(()).with_stack(inet::init);
    app.node("a", WithoutChecks::default());
    app.node("b", WithoutChecks::default());

    let ag = app.gate("a", "port");
    let bg = app.gate("b", "port");

    let chan = DatarateChannel::new(DatarateChannelMetrics {
        bitrate: 1000000,
        latency: Duration::from_millis(50),
        jitter: Duration::ZERO,
        drop_behaviour: ChannelDropBehaviour::Drop,
    });
    ag.connect_with(bg, Some(chan));

    let rt = Builder::seeded(123).build(app.freeze());
    rt.run().map(|_| ())
}

#[test]
#[serial]
fn tentative_addr_no_checks_on_manual_no_dedup() -> Result<(), RuntimeError> {
    // des::tracing::init();

    let mut app = Sim::new(()).with_stack(inet::init);
    app.node("a", ManualAssignWithoutDedup::default());
    app.node("b", OnlyRouterSolOrMDL::default());

    let ag = app.gate("a", "port");
    let bg = app.gate("b", "port");

    let chan = DatarateChannel::new(DatarateChannelMetrics {
        bitrate: 1000000,
        latency: Duration::from_millis(50),
        jitter: Duration::ZERO,
        drop_behaviour: ChannelDropBehaviour::Drop,
    });
    ag.connect_with(bg, Some(chan));

    let rt = Builder::seeded(123).build(app.freeze());
    rt.run().map(|_| ())
}

#[test]
#[serial]
fn tentative_addr_collision() -> Result<(), RuntimeError> {
    // des::tracing::init();

    let mut app = Sim::new(()).with_stack(inet::init);
    app.node("a", AssignSameAddr::default());
    app.node("b", AssignSameAddr::default());

    let ag = app.gate("a", "port");
    let bg = app.gate("b", "port");

    let chan = DatarateChannel::new(DatarateChannelMetrics {
        bitrate: 1000000,
        latency: Duration::from_millis(50),
        jitter: Duration::ZERO,
        drop_behaviour: ChannelDropBehaviour::Drop,
    });
    ag.connect_with(bg, Some(chan));

    let rt = Builder::seeded(123).build(app.freeze());
    rt.run().map(|_| ())
}

#[test]
#[serial]
fn interface_handle_wait_for_link_local() -> Result<(), RuntimeError> {
    // des::tracing::init();

    let mut sim = Sim::new(()).with_stack(inet::init);
    sim.node(
        "sender",
        AsyncHandler::failable::<_, _, std::io::Error>(|_| async move {
            let mut handle =
                ioctx().add_interface(InterfaceDef::new("en0", NetworkDevice::eth()).v6())?;
            handle.wait_for_link_local().await;
            assert_eq!(SimTime::now(), 1.0);
            Ok(())
        }),
    );

    sim.node(
        "receiver",
        AsyncHandler::failable::<_, _, std::io::Error>(|_| async move {
            let mut handle =
                ioctx().add_interface(InterfaceDef::new("en0", NetworkDevice::eth()).v6())?;
            handle.wait_for_link_local().await;
            assert_eq!(SimTime::now(), 1.0);
            Ok(())
        }),
    );

    let so = sim.gate("sender", "port");
    let co = sim.gate("receiver", "port");

    so.connect_with(
        co,
        Some(DatarateChannel::new(DatarateChannelMetrics {
            bitrate: 1000_000,
            latency: Duration::from_millis(20),
            jitter: Duration::ZERO,
            drop_behaviour: ChannelDropBehaviour::Queue(None),
        })),
    );

    let rt = Builder::seeded(123).build(sim.freeze());
    let result = rt.run().map(|_| ());

    result
}

#[test]
#[serial]
fn interface_handle_wait_for_global() -> Result<(), RuntimeError> {
    // des::tracing::init();

    let mut sim = Sim::new(()).with_stack(inet::init);
    sim.node(
        "client",
        AsyncHandler::failable::<_, _, std::io::Error>(|_| async move {
            let mut handle =
                ioctx().add_interface(InterfaceDef::new("en0", NetworkDevice::eth()).v6())?;
            handle.wait_for_global().await;
            assert!(SimTime::now() > 1.0.into());
            Ok(())
        })
        .require_join(),
    );
    sim.node("router", Router);

    let so = sim.gate("client", "port");
    let co = sim.gate("router", "port");

    so.connect_with(
        co,
        Some(DatarateChannel::new(DatarateChannelMetrics {
            bitrate: 1000_000,
            latency: Duration::from_millis(20),
            jitter: Duration::ZERO,
            drop_behaviour: ChannelDropBehaviour::Queue(None),
        })),
    );

    let rt = Builder::seeded(123)
        .max_time(10.0.into())
        .build(sim.freeze());
    let result = rt.run().map(|_| ());

    result
}
