use std::fs::File;

use des::{
    ndl::NdlApplication,
    net::module::{AsyncModule, Module},
    registry,
    runtime::Builder,
};
use inet::{
    interface::{add_interface, Interface, NetworkDevice},
    ipv6::util::setup_router,
    routing::RoutingPort,
    utils::{self, getaddrinfo},
};
use inet_pcap::{pcap, PcapCapturePoints, PcapConfig, PcapFilters};

#[macro_use]
mod common;

struct HostAlice;
impl_build_named!(HostAlice);

impl AsyncModule for HostAlice {
    fn new() -> Self {
        Self
    }

    async fn at_sim_start(&mut self, _stage: usize) {
        pcap(PcapConfig {
            filters: PcapFilters::default(),
            capture: PcapCapturePoints::All,
            output: File::create("out/ipv6_tentative_alice.pcap").unwrap(),
        })
        .unwrap();

        add_interface(Interface::empty("en0", NetworkDevice::eth())).unwrap();
    }

    async fn at_sim_end(&mut self) {
        let addrs = getaddrinfo().unwrap();
        assert_eq!(addrs.len(), 3);
    }
}

struct HostBob;
impl_build_named!(HostBob);

impl AsyncModule for HostBob {
    fn new() -> Self {
        Self
    }

    async fn at_sim_start(&mut self, _stage: usize) {
        pcap(PcapConfig {
            filters: PcapFilters::default(),
            capture: PcapCapturePoints::All,
            output: File::create("out/ipv6_tentative_bob.pcap").unwrap(),
        })
        .unwrap();

        add_interface(Interface::empty("en0", NetworkDevice::eth())).unwrap();
    }

    async fn at_sim_end(&mut self) {
        let addrs = getaddrinfo().unwrap();
        assert_eq!(addrs.len(), 3);
    }
}

struct Router;
impl_build_named!(Router);

impl AsyncModule for Router {
    fn new() -> Self {
        Self
    }

    async fn at_sim_start(&mut self, _stage: usize) {
        pcap(PcapConfig {
            filters: PcapFilters::default(),
            capture: PcapCapturePoints::All,
            output: File::create("out/ipv6_tentative_router.pcap").unwrap(),
        })
        .unwrap();

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

type Switch = utils::LinkLayerSwitch;

struct Main;
impl_build_named!(Main);
impl Module for Main {
    fn new() -> Self {
        Main
    }
}

#[test]
fn ipv6_tentative_addrs() {
    inet::init();
    des::tracing::init();

    let app = NdlApplication::new(
        "tests/ipv6.ndl",
        registry![Main, HostAlice, HostBob, Router, Switch],
    )
    .unwrap();

    let rt = Builder::seeded(123)
        // .max_itr(30)
        .max_time(10.0.into())
        .build(app.into_app());
    let _ = rt.run();
}
