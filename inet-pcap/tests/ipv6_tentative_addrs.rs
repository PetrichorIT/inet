use std::fs::File;

use des::{
    net::{module::Module, Sim},
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

impl Module for HostAlice {
    fn at_sim_start(&mut self, _stage: usize) {
        pcap(PcapConfig {
            filters: PcapFilters::default(),
            capture: PcapCapturePoints::All,
            output: File::create("out/ipv6_tentative_alice.pcap").unwrap(),
        })
        .unwrap();

        add_interface(Interface::empty("en0", NetworkDevice::eth())).unwrap();
    }

    fn at_sim_end(&mut self) {
        let addrs = getaddrinfo().unwrap();
        assert_eq!(addrs.len(), 3);
    }
}

#[derive(Default)]
struct HostBob;

impl Module for HostBob {
    fn at_sim_start(&mut self, _stage: usize) {
        pcap(PcapConfig {
            filters: PcapFilters::default(),
            capture: PcapCapturePoints::All,
            output: File::create("out/ipv6_tentative_bob.pcap").unwrap(),
        })
        .unwrap();

        add_interface(Interface::empty("en0", NetworkDevice::eth())).unwrap();
    }

    fn at_sim_end(&mut self) {
        let addrs = getaddrinfo().unwrap();
        assert_eq!(addrs.len(), 3);
    }
}

#[derive(Default)]
struct Router;

impl Module for Router {
    fn at_sim_start(&mut self, _stage: usize) {
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
    // des::tracing::init();

    let app = Sim::new(())
        .with_stack(inet::init)
        .with_ndl(
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
