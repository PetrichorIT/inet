use std::fs::File;

use des::module::Module;

use inet::{
    env::RoutingPort,
    interface::{InterfaceDef, NetworkDevice},
    ioctx,
    ipv6::util::setup_router,
    utils::{SimpleSim, getaddrinfo},
};
use inet_pcap::pcap;

#[derive(Default)]
struct HostAlice;

impl Module for HostAlice {
    fn at_sim_start(&mut self, _stage: usize) {
        pcap(File::create("out/ipv6_tentative_alice.pcap").unwrap()).unwrap();

        ioctx()
            .add_interface(InterfaceDef::new("en0", NetworkDevice::eth()).v6())
            .unwrap();
    }

    fn at_sim_end(&mut self) -> Result<(), des::Error> {
        let addrs = getaddrinfo().unwrap();
        assert_eq!(addrs.len(), 3);
        Ok(())
    }
}

#[derive(Default)]
struct HostBob;

impl Module for HostBob {
    fn at_sim_start(&mut self, _stage: usize) {
        pcap(File::create("out/ipv6_tentative_bob.pcap").unwrap()).unwrap();

        ioctx()
            .add_interface(InterfaceDef::new("en0", NetworkDevice::eth()).v6())
            .unwrap();
    }

    fn at_sim_end(&mut self) -> Result<(), des::Error> {
        let addrs = getaddrinfo().unwrap();
        assert_eq!(addrs.len(), 3);
        Ok(())
    }
}

#[derive(Default)]
struct Router;

impl Module for Router {
    fn at_sim_start(&mut self, _stage: usize) {
        pcap(File::create("out/ipv6_tentative_router.pcap").unwrap()).unwrap();

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

#[test]
fn ipv6_tentative_addrs() -> Result<(), des::Failure> {
    // des::tracing::init();

    let mut sim = SimpleSim::default();
    sim.module("alice", HostAlice);
    sim.module("bob", HostBob);
    sim.module("router", Router);

    sim.run_max_time(10.0)?;
    Ok(())
}
