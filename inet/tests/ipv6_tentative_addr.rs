use std::time::Duration;

use bytepack::FromBytestream;
use des::{
    net::{
        channel::{Channel, ChannelDropBehaviour, ChannelMetrics},
        module::{AsyncModule, Module},
        Sim,
    },
    runtime::Builder,
};
use inet::{
    interface::{add_interface, interface_status, Interface, NetworkDevice},
    ipv6::{api::set_node_cfg, cfg::HostConfiguration},
};
use inet_types::{icmpv6::IcmpV6Packet, iface::MacAddress, ip::Ipv6Packet};
use serial_test::serial;

#[derive(Default)]
struct WithChecks;

impl AsyncModule for WithChecks {
    async fn at_sim_start(&mut self, _stage: usize) {
        add_interface(Interface::empty("en0", NetworkDevice::eth())).unwrap();

        let state = interface_status("en0").unwrap();
        assert_eq!(state.addrs.iter().count(), 0);
        assert_eq!(state.addrs.multicast_scopes().len(), 1); // sol-multicast (delayed) + all nodes multicast
    }

    async fn at_sim_end(&mut self) {
        let state = interface_status("en0").unwrap();
        assert_eq!(state.addrs.iter().count(), 1);
        assert_eq!(state.addrs.multicast_scopes().len(), 2); // sol-multicast (delayed) + all nodes multicast
    }
}

#[derive(Default)]
struct WithoutChecks;

impl AsyncModule for WithoutChecks {
    async fn at_sim_start(&mut self, _stage: usize) {
        set_node_cfg(HostConfiguration {
            dup_addr_detect_transmits: 0,
            ..Default::default()
        })
        .unwrap();

        add_interface(Interface::empty("en0", NetworkDevice::eth())).unwrap();
        let state = interface_status("en0").unwrap();
        assert_eq!(state.addrs.iter().count(), 1);
        assert_eq!(state.addrs.multicast_scopes().len(), 2); // sol-multicast + all nodes multicast
    }

    async fn at_sim_end(&mut self) {
        let state = interface_status("en0").unwrap();
        assert_eq!(state.addrs.iter().count(), 1);
        assert_eq!(state.addrs.multicast_scopes().len(), 2); // sol-multicast + all nodes multicast
    }
}

#[derive(Default)]
struct ManualAssignWithoutDedup;

impl AsyncModule for ManualAssignWithoutDedup {
    async fn at_sim_start(&mut self, _stage: usize) {
        add_interface(Interface::ethv6_named_linklocal(
            "en0",
            NetworkDevice::eth(),
        ))
        .unwrap();

        let state = interface_status("en0").unwrap();
        assert_eq!(state.addrs.iter().count(), 1);
        assert_eq!(state.addrs.multicast_scopes().len(), 2); // sol-multicast + all nodes multicast
    }

    async fn at_sim_end(&mut self) {
        let state = interface_status("en0").unwrap();
        assert_eq!(state.addrs.iter().count(), 1);
        assert_eq!(state.addrs.multicast_scopes().len(), 2); // sol-multicast + all nodes multicast
    }
}

#[derive(Default)]
struct OnlyRouterSolOrMDL;

impl Module for OnlyRouterSolOrMDL {
    fn handle_message(&mut self, msg: des::prelude::Message) {
        let pkt = msg.content::<Ipv6Packet>();
        let icmp = IcmpV6Packet::from_slice(&pkt.content).unwrap();
        assert!(matches!(
            icmp,
            IcmpV6Packet::RouterSolicitation(_) | IcmpV6Packet::MulticastListenerReport(_)
        ));
    }
}

#[derive(Default)]
struct AssignSameAddr;

impl AsyncModule for AssignSameAddr {
    async fn at_sim_start(&mut self, _: usize) {
        let mut device = NetworkDevice::eth();
        let mac = MacAddress::from([1, 2, 3, 4, 5, 6]);
        assert!(!mac.is_multicast());
        device.addr = mac;
        add_interface(Interface::empty("en0", device)).unwrap();
    }

    async fn at_sim_end(&mut self) {
        assert!(interface_status("en0")
            .unwrap()
            .addrs
            .iter()
            .collect::<Vec<_>>()
            .is_empty());
    }
}

#[test]
#[serial]
fn tentative_addr_with_checks() {
    inet::init();
    // des::tracing::init();

    let mut app = Sim::new(());
    app.node("a", WithChecks::default());
    app.node("b", WithChecks::default());

    let ag = app.gate("a", "port");
    let bg = app.gate("b", "port");

    let chan = Channel::new(ChannelMetrics {
        bitrate: 1000000,
        latency: Duration::from_millis(50),
        jitter: Duration::ZERO,
        drop_behaviour: ChannelDropBehaviour::Drop,
    });
    ag.connect(bg, Some(chan));

    let rt = Builder::seeded(123).build(app);
    let _ = rt.run();
}

#[test]
#[serial]
fn tentative_addr_without_checks() {
    inet::init();
    // des::tracing::init();

    let mut app = Sim::new(());
    app.node("a", WithoutChecks::default());
    app.node("b", WithoutChecks::default());

    let ag = app.gate("a", "port");
    let bg = app.gate("b", "port");

    let chan = Channel::new(ChannelMetrics {
        bitrate: 1000000,
        latency: Duration::from_millis(50),
        jitter: Duration::ZERO,
        drop_behaviour: ChannelDropBehaviour::Drop,
    });
    ag.connect(bg, Some(chan));

    let rt = Builder::seeded(123).build(app);
    let _ = rt.run();
}

#[test]
#[serial]
fn tentative_addr_no_checks_on_manual_no_dedup() {
    inet::init();
    // des::tracing::init();

    let mut app = Sim::new(());
    app.node("a", ManualAssignWithoutDedup::default());
    app.node("b", OnlyRouterSolOrMDL::default());

    let ag = app.gate("a", "port");
    let bg = app.gate("b", "port");

    let chan = Channel::new(ChannelMetrics {
        bitrate: 1000000,
        latency: Duration::from_millis(50),
        jitter: Duration::ZERO,
        drop_behaviour: ChannelDropBehaviour::Drop,
    });
    ag.connect(bg, Some(chan));

    let rt = Builder::seeded(123).build(app);
    let _ = rt.run();
}

#[test]
#[serial]
fn tentative_addr_collision() {
    inet::init();
    // des::tracing::init();

    let mut app = Sim::new(());
    app.node("a", AssignSameAddr::default());
    app.node("b", AssignSameAddr::default());

    let ag = app.gate("a", "port");
    let bg = app.gate("b", "port");

    let chan = Channel::new(ChannelMetrics {
        bitrate: 1000000,
        latency: Duration::from_millis(50),
        jitter: Duration::ZERO,
        drop_behaviour: ChannelDropBehaviour::Drop,
    });
    ag.connect(bg, Some(chan));

    let rt = Builder::seeded(123).build(app);
    let _ = rt.run();
}
