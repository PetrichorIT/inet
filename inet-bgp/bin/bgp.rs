use std::fs::File;

use des::{
    prelude::*,
    registry,
    tokio::spawn,
    tracing::{NoColorFormatter, ScopeConfiguration, ScopeConfigurationPolicy, Subscriber},
};
use inet::{
    interface::{add_interface, Interface, NetworkDevice},
    pcap::{pcap, PcapCapturePoints, PcapConfig, PcapFilters},
};
use inet_bgp::BgpDeamon;
use tracing::metadata::LevelFilter;

struct A;
#[async_trait::async_trait]
impl AsyncModule for A {
    fn new() -> Self {
        Self
    }

    async fn at_sim_start(&mut self, _: usize) {
        add_interface(Interface::ethv4(
            NetworkDevice::eth(),
            Ipv4Addr::new(192, 168, 0, 101),
        ))
        .unwrap();

        pcap(PcapConfig {
            filters: PcapFilters::default(),
            capture: PcapCapturePoints::CLIENT_DEFAULT,
            output: File::create("bin/a.pcap").unwrap(),
        })
        .unwrap();

        spawn(
            BgpDeamon::new(1000, Ipv4Addr::new(192, 168, 0, 101))
                .add_neighbor(Ipv4Addr::new(192, 168, 0, 102), 2000)
                .deploy(),
        );
    }
}

// ffffffffffffffffffffffffffffffff 00 1d 0104 fe09 00b4c 0a8006500
// ffffffffffffffffffffffffffffffff 00 1d 0104 fe09 00b4c 0a8000f00

struct B;
#[async_trait::async_trait]
impl AsyncModule for B {
    fn new() -> Self {
        Self
    }

    async fn at_sim_start(&mut self, _: usize) {
        add_interface(Interface::ethv4(
            NetworkDevice::eth(),
            Ipv4Addr::new(192, 168, 0, 102),
        ))
        .unwrap();

        pcap(PcapConfig {
            filters: PcapFilters::default(),
            capture: PcapCapturePoints::CLIENT_DEFAULT,
            output: File::create("bin/b.pcap").unwrap(),
        })
        .unwrap();

        spawn(
            BgpDeamon::new(1000, Ipv4Addr::new(192, 168, 0, 102))
                .add_neighbor(Ipv4Addr::new(192, 168, 0, 101), 1000)
                .deploy(),
        );
    }
}

struct Main;
impl Module for Main {
    fn new() -> Self {
        Self
    }
}

fn main() {
    inet::init();

    struct Policy;
    impl ScopeConfigurationPolicy for Policy {
        fn configure(&self, scope: &str) -> ScopeConfiguration {
            ScopeConfiguration {
                fmt: Box::new(NoColorFormatter),
                output: Box::new(std::io::stdout()),
            }
        }
    }

    Subscriber::new(Policy)
        .with_max_level(LevelFilter::TRACE)
        .init()
        .unwrap();

    let app =
        NetworkApplication::new(NdlApplication::new("bin/pkt.ndl", registry![A, B, Main]).unwrap());
    let rt = Runtime::new_with(
        app,
        RuntimeOptions::seeded(123)
            .max_time(1000.0.into())
            .max_itr(1000),
    );
    let _ = rt.run();
}
