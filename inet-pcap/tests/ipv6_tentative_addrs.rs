use std::fs::File;

use des::{
    net::{module::AsyncModule, Sim},
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

#[derive(Default)]
struct HostAlice;

impl AsyncModule for HostAlice {
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

#[derive(Default)]
struct HostBob;

impl AsyncModule for HostBob {
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

#[derive(Default)]
struct Router;

impl AsyncModule for Router {
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

#[test]
fn ipv6_tentative_addrs() {
    inet::init();
    // des::tracing::init();

    let app = Sim::ndl(
        "tests/ipv6.ndl",
        registry![HostAlice, HostBob, Router, Switch, else _],
    )
    .unwrap();

    let rt = Builder::seeded(123)
        // .max_itr(30)
        .max_time(10.0.into())
        .build(app);
    let _ = rt.run();
}
