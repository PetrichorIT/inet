use std::time::Duration;

use bytes_io::FromBytes;
use des::{
    net::{
        channel::{ChannelDropBehaviour, DatarateChannel, DatarateChannelMetrics},
        module::Module,
        Sim,
    },
    runtime::{Builder, RuntimeError},
};
use inet::{
    interface::{add_interface, interface_status, InterfaceDef, NetworkDevice},
    ipv6::{api::set_node_cfg, cfg::HostConfiguration},
};
use serial_test::serial;
use types::{icmpv6::IcmpV6Packet, iface::MacAddress, ip::Ipv6Packet};

#[derive(Default)]
struct WithChecks;

impl Module for WithChecks {
    fn at_sim_start(&mut self, _stage: usize) {
        add_interface(InterfaceDef::new("en0", NetworkDevice::eth()).v6()).unwrap();

        let state = interface_status("en0").unwrap();
        assert_eq!(state.addrs.addrs().count(), 0);
        assert_eq!(state.addrs.multicast_scopes().len(), 1); // sol-multicast (delayed) + all nodes multicast
    }

    fn at_sim_end(&mut self) -> Result<(), RuntimeError> {
        let state = interface_status("en0").unwrap();
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

        add_interface(InterfaceDef::new("en0", NetworkDevice::eth()).v6()).unwrap();
        let state = interface_status("en0").unwrap();
        assert_eq!(state.addrs.addrs().count(), 1);
        assert_eq!(state.addrs.multicast_scopes().len(), 2); // sol-multicast + all nodes multicast
    }

    fn at_sim_end(&mut self) -> Result<(), RuntimeError> {
        let state = interface_status("en0").unwrap();
        assert_eq!(state.addrs.addrs().count(), 1);
        assert_eq!(state.addrs.multicast_scopes().len(), 2); // sol-multicast + all nodes multicast
        Ok(())
    }
}

#[derive(Default)]
struct ManualAssignWithoutDedup;

impl Module for ManualAssignWithoutDedup {
    fn at_sim_start(&mut self, _stage: usize) {
        add_interface(InterfaceDef::ethv6_autocfg(NetworkDevice::eth())).unwrap();

        let state = interface_status("en0").unwrap();
        assert_eq!(state.addrs.addrs().count(), 1);
        assert_eq!(state.addrs.multicast_scopes().len(), 2); // sol-multicast + all nodes multicast
    }

    fn at_sim_end(&mut self) -> Result<(), RuntimeError> {
        let state = interface_status("en0").unwrap();
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
        add_interface(InterfaceDef::new("en0", device)).unwrap();
    }

    fn at_sim_end(&mut self) -> Result<(), RuntimeError> {
        assert!(interface_status("en0")
            .unwrap()
            .addrs
            .addrs()
            .collect::<Vec<_>>()
            .is_empty());
        Ok(())
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
