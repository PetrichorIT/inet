use des::net::module::Module;

use inet::{
    env::RoutingPort,
    interface::{InterfaceDef, NetworkDevice},
    ioctx,
    ipv6::{router, util::setup_router},
    utils::{SimpleSim, getaddrinfo},
};
use inet_pcap::pcap;
use serial_test::serial;
use std::fs::File;

#[derive(Default)]
struct Expect3Addrs;

impl Module for Expect3Addrs {
    fn at_sim_start(&mut self, _stage: usize) {
        pcap(File::create("out/ipv6_timeout_alice.pcap").unwrap()).unwrap();

        ioctx()
            .add_interface(InterfaceDef::new("en0", NetworkDevice::eth()).v6())
            .unwrap();
    }

    fn at_sim_end(&mut self) -> Result<(), des::net::Error> {
        let addrs = getaddrinfo().unwrap();
        assert_eq!(addrs.len(), 3, "see: {addrs:?}");
        Ok(())
    }
}

#[derive(Default)]
struct Expect3Then1Addrs;

impl Module for Expect3Then1Addrs {
    fn at_sim_start(&mut self, _stage: usize) {
        pcap(File::create("out/ipv6_timeout_bob.pcap").unwrap()).unwrap();

        ioctx()
            .add_interface(InterfaceDef::new("en0", NetworkDevice::eth()).v6())
            .unwrap();
    }

    fn at_sim_end(&mut self) -> Result<(), des::net::Error> {
        let addrs = getaddrinfo().unwrap();
        assert_eq!(addrs.len(), 1);
        Ok(())
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
        router::declare_router().unwrap();

        for port in RoutingPort::collect() {
            router::add_routing_interface(
                format!("en-{}", port.output.str()),
                NetworkDevice::from(port),
                &[
                    "2003:c1:e719:8fff::1".parse().unwrap(),
                    "2003:c1:e719:1234::1".parse().unwrap(),
                ],
                false,
            )
            .unwrap();
        }
    }
}

#[test]
#[serial]
fn ipv6_timeouts_with_ra() -> Result<(), des::net::Failure> {
    // des::tracing::init();

    let mut sim = SimpleSim::default();
    sim.module("alice", Expect3Addrs);
    sim.module("bob", Expect3Addrs);
    sim.module("router", RouterWithAdv);

    sim.run_max_time(10.0)?;
    Ok(())
}

#[test]
#[serial]
fn ipv6_timeouts_without_ra() -> Result<(), des::net::Failure> {
    // des::tracing::init();

    let mut sim = SimpleSim::default();
    sim.module("alice", Expect3Then1Addrs);
    sim.module("bob", Expect3Then1Addrs);
    sim.module("router", RouterWithoutAdv);

    sim.run_max_time(10.0)?;
    Ok(())
}
