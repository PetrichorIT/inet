use std::time::Duration;

use bytepack::FromBytestream;
use des::{
    net::{
        channel::{Channel, ChannelDropBehaviour, ChannelMetrics},
        module::{AsyncModule, Module},
        NetworkApplication,
    },
    runtime::Builder,
};
use inet::{
    interface::{add_interface, interface_status, Interface, NetworkDevice},
    ipv6::{api::set_node_cfg, cfg::HostConfiguration},
};
use inet_types::{icmpv6::IcmpV6Packet, ip::Ipv6Packet};

#[macro_use]
mod common;

struct WithChecks;
impl_build_named!(WithChecks);

impl AsyncModule for WithChecks {
    fn new() -> Self {
        Self
    }

    #[tracing::instrument(skip(self))]
    async fn at_sim_start(&mut self, _stage: usize) {
        add_interface(Interface::empty("en0", NetworkDevice::eth())).unwrap();

        let state = interface_status("en0").unwrap();
        assert_eq!(state.addrs.len(), 0);
        assert_eq!(state.mutlicast_scopes.len(), 2); // sol-multicast + all nodes multicast
    }

    async fn at_sim_end(&mut self) {
        let state = interface_status("en0").unwrap();
        assert_eq!(state.addrs.len(), 1);
        assert_eq!(state.mutlicast_scopes.len(), 2); // sol-multicast + all nodes multicast
    }
}

struct WithoutChecks;
impl_build_named!(WithoutChecks);

impl AsyncModule for WithoutChecks {
    fn new() -> Self {
        Self
    }

    async fn at_sim_start(&mut self, _stage: usize) {
        set_node_cfg(HostConfiguration {
            dup_addr_detect_transmits: 0,
            ..Default::default()
        })
        .unwrap();

        add_interface(Interface::empty("en0", NetworkDevice::eth())).unwrap();
        let state = interface_status("en0").unwrap();
        assert_eq!(state.addrs.len(), 1);
        assert_eq!(state.mutlicast_scopes.len(), 2); // sol-multicast + all nodes multicast
    }

    async fn at_sim_end(&mut self) {
        let state = interface_status("en0").unwrap();
        assert_eq!(state.addrs.len(), 1);
        assert_eq!(state.mutlicast_scopes.len(), 2); // sol-multicast + all nodes multicast
    }
}

struct ManualAssignWithoutDedup;
impl_build_named!(ManualAssignWithoutDedup);

impl AsyncModule for ManualAssignWithoutDedup {
    fn new() -> Self {
        Self
    }

    async fn at_sim_start(&mut self, _stage: usize) {
        add_interface(Interface::ethv6_named_linklocal(
            "en0",
            NetworkDevice::eth(),
        ))
        .unwrap();

        let state = interface_status("en0").unwrap();
        assert_eq!(state.addrs.len(), 1);
        assert_eq!(state.mutlicast_scopes.len(), 2); // sol-multicast + all nodes multicast
    }

    async fn at_sim_end(&mut self) {
        let state = interface_status("en0").unwrap();
        assert_eq!(state.addrs.len(), 1);
        assert_eq!(state.mutlicast_scopes.len(), 2); // sol-multicast + all nodes multicast
    }
}

struct ShouldOnlyGetRouterSol;
impl_build_named!(ShouldOnlyGetRouterSol);

impl Module for ShouldOnlyGetRouterSol {
    fn new() -> Self {
        Self
    }
    fn handle_message(&mut self, msg: des::prelude::Message) {
        let pkt = msg.content::<Ipv6Packet>();
        let icmp = IcmpV6Packet::from_slice(&pkt.content).unwrap();
        assert!(matches!(icmp, IcmpV6Packet::RouterSolicitation(_)));
    }
}

#[test]
#[serial_test::serial]
fn tentative_addr_with_checks() {
    inet::init();
    // des::tracing::Subscriber::default().init().unwrap();
    des::tracing::init();

    let mut app = NetworkApplication::new(());
    let h0 = WithChecks::build_named("a".into(), &mut app);
    let h1 = WithChecks::build_named("b".into(), &mut app);

    let h0p = h0.create_gate("port");
    let h1p = h1.create_gate("port");

    let chan = Channel::new(
        h0.path().appended_channel("chan"),
        ChannelMetrics {
            bitrate: 1000000,
            latency: Duration::from_millis(50),
            jitter: Duration::ZERO,
            drop_behaviour: ChannelDropBehaviour::Drop,
        },
    );
    h0p.connect(h1p, Some(chan));

    app.register_module(h0);
    app.register_module(h1);

    let rt = Builder::seeded(123).build(app);
    let _ = rt.run();
}

#[test]
#[serial_test::serial]
fn tentative_addr_without_checks() {
    inet::init();
    // des::tracing::Subscriber::default().init().unwrap();

    let mut app = NetworkApplication::new(());
    let h0 = WithoutChecks::build_named("a".into(), &mut app);
    let h1 = WithoutChecks::build_named("b".into(), &mut app);

    let h0p = h0.create_gate("port");
    let h1p = h1.create_gate("port");

    let chan = Channel::new(
        h0.path().appended_channel("chan"),
        ChannelMetrics {
            bitrate: 1000000,
            latency: Duration::from_millis(50),
            jitter: Duration::ZERO,
            drop_behaviour: ChannelDropBehaviour::Drop,
        },
    );
    h0p.connect(h1p, Some(chan));

    app.register_module(h0);
    app.register_module(h1);

    let rt = Builder::seeded(123).build(app);
    let _ = rt.run();
}

#[test]
#[serial_test::serial]
fn tentative_addr_no_checks_on_manual_no_dedup() {
    inet::init();
    // des::tracing::Subscriber::default().init().unwrap();

    let mut app = NetworkApplication::new(());
    let h0 = ManualAssignWithoutDedup::build_named("a".into(), &mut app);
    let h1 = ShouldOnlyGetRouterSol::build_named("b".into(), &mut app);

    let h0p = h0.create_gate("port");
    let h1p = h1.create_gate("port");

    let chan = Channel::new(
        h0.path().appended_channel("chan"),
        ChannelMetrics {
            bitrate: 1000000,
            latency: Duration::from_millis(50),
            jitter: Duration::ZERO,
            drop_behaviour: ChannelDropBehaviour::Drop,
        },
    );
    h0p.connect(h1p, Some(chan));

    app.register_module(h0);
    app.register_module(h1);

    let rt = Builder::seeded(123).build(app);
    let _ = rt.run();
}
