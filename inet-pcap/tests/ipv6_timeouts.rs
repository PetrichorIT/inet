use des::{
    net::{module::Module, Sim},
    registry,
    runtime::Builder,
};
use inet::{
    interface::{add_interface, Interface, InterfaceAddr, NetworkDevice},
    ipv6::util::setup_router,
    routing::{declare_ipv6_router, Ipv6RouterConfig, RoutingPort},
    utils::{self, getaddrinfo},
};
use inet_pcap::pcap;
use serial_test::serial;
use std::fs::File;

#[derive(Default)]
struct Expect3Addrs;

impl Module for Expect3Addrs {
    fn at_sim_start(&mut self, _stage: usize) {
        pcap(File::create("out/ipv6_timeout_alice.pcap").unwrap()).unwrap();

        add_interface(Interface::empty("en0", NetworkDevice::eth())).unwrap();
    }

    fn at_sim_end(&mut self) {
        let addrs = getaddrinfo().unwrap();
        assert_eq!(addrs.len(), 3, "see: {addrs:?}");
    }
}

#[derive(Default)]
struct Expect3Then1Addrs;

impl Module for Expect3Then1Addrs {
    fn at_sim_start(&mut self, _stage: usize) {
        pcap(File::create("out/ipv6_timeout_bob.pcap").unwrap()).unwrap();

        add_interface(Interface::empty("en0", NetworkDevice::eth())).unwrap();
    }

    fn at_sim_end(&mut self) {
        let addrs = getaddrinfo().unwrap();
        assert_eq!(addrs.len(), 1);
    }
}

#[derive(Default)]
struct RouterWithAdv;

impl Module for RouterWithAdv {
    fn at_sim_start(&mut self, _stage: usize) {
        pcap(File::create("out/ipv6_timeout_router.pcap").unwrap()).unwrap();

        setup_router(
            "fe80::1111:2222".parse().unwrap(),
            RoutingPort::collect(),
            vec![
                "2003:c1:e719:8fff::/64".parse().unwrap(),
                "2003:c1:e719:1234::/64".parse().unwrap(),
            ],
        )
        .unwrap();
    }
}

#[derive(Default)]
struct RouterWithoutAdv;

impl Module for RouterWithoutAdv {
    fn at_sim_start(&mut self, _stage: usize) {
        pcap(File::create("out/ipv6_timeout_router.pcap").unwrap()).unwrap();

        for port in RoutingPort::collect() {
            let mut iface = Interface::empty(
                &format!("en-{}", port.output.str()),
                NetworkDevice::from(port),
            );
            iface
                .addrs
                .add(InterfaceAddr::ipv6_link_local(iface.device.addr));
            iface.flags.router = true;
            add_interface(iface).unwrap();
        }

        declare_ipv6_router(Ipv6RouterConfig {
            adv: false,
            prefixes: vec![
                "2003:c1:e719:8fff::/64".parse().unwrap(),
                "2003:c1:e719:1234::/64".parse().unwrap(),
            ],
            ..Default::default()
        })
        .unwrap();
    }
}

type Switch = utils::LinkLayerSwitch;

#[test]
#[serial]
fn ipv6_timeouts_with_ra() {
    // des::tracing::init();

    type Router = RouterWithAdv;
    type HostAlice = Expect3Addrs;
    type HostBob = Expect3Addrs;

    let app = Sim::new(())
        .with_stack(inet::init)
        .with_ndl(
            "tests/ipv6.yml",
            registry![HostAlice, HostBob, Router, Switch, else _],
        )
        .unwrap();

    let rt = Builder::seeded(123)
        // .max_itr(30)
        .max_time(10_000.0.into())
        .build(app);
    let _ = rt.run();
}

#[test]
#[serial]
fn ipv6_timeouts_without_ra() {
    // des::tracing::init();

    type Router = RouterWithoutAdv;
    type HostAlice = Expect3Then1Addrs;
    type HostBob = Expect3Then1Addrs;

    let app = Sim::new(())
        .with_stack(inet::init)
        .with_ndl(
            "tests/ipv6.yml",
            registry![HostAlice, HostBob, Router, Switch, else _],
        )
        .unwrap();

    let rt = Builder::seeded(123)
        // .max_itr(30)
        .max_time(10_000.0.into())
        .build(app);
    let _ = rt.run();
}
