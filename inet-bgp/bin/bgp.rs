use std::fs::File;

use des::{prelude::*, registry};
use inet::{
    interface::{add_interface, Interface, NetworkDevice},
    routing::route,
};
use inet_bgp::{pkt::Nlri, BgpDeamon};
use inet_pcap::{pcap, PcapCapturePoints, PcapConfig, PcapFilters};
use tokio::spawn;

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
            capture: PcapCapturePoints::All,
            output: File::create("bin/a.pcap").unwrap(),
        })
        .unwrap();

        spawn(
            BgpDeamon::new(1000, Ipv4Addr::new(192, 168, 0, 101))
                .add_neighbor(Ipv4Addr::new(192, 168, 0, 102), 2000, "en0")
                .add_nlri(Nlri::new(Ipv4Addr::new(10, 0, 2, 0), 24))
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
        add_interface(Interface::ethv4_named(
            "link-a",
            NetworkDevice::eth_select(|p| p.input.name().starts_with("a")),
            Ipv4Addr::new(192, 168, 0, 102),
            Ipv4Addr::new(255, 255, 255, 0),
        ))
        .unwrap();
        add_interface(Interface::ethv4_named(
            "link-c",
            NetworkDevice::eth_select(|p| p.input.name().starts_with("c")),
            Ipv4Addr::new(192, 168, 0, 102),
            Ipv4Addr::new(255, 255, 255, 0),
        ))
        .unwrap();

        pcap(PcapConfig {
            filters: PcapFilters::default(),
            capture: PcapCapturePoints::All,
            output: File::create("bin/b.pcap").unwrap(),
        })
        .unwrap();

        spawn(
            BgpDeamon::new(2000, Ipv4Addr::new(192, 168, 0, 102))
                .add_neighbor(Ipv4Addr::new(192, 168, 0, 101), 1000, "link-a")
                .add_neighbor(Ipv4Addr::new(192, 168, 0, 103), 3000, "link-c")
                .add_nlri(Nlri::new(Ipv4Addr::new(20, 3, 8, 0), 24))
                .deploy(),
        );
    }
}

struct C;
#[async_trait::async_trait]
impl AsyncModule for C {
    fn new() -> Self {
        Self
    }

    async fn at_sim_start(&mut self, _: usize) {
        add_interface(Interface::ethv4_named(
            "link-b",
            NetworkDevice::eth_select(|p| p.input.name().starts_with("b")),
            Ipv4Addr::new(192, 168, 0, 103),
            Ipv4Addr::new(255, 255, 255, 0),
        ))
        .unwrap();
        add_interface(Interface::ethv4_named(
            "link-d",
            NetworkDevice::eth_select(|p| p.input.name().starts_with("d")),
            Ipv4Addr::new(192, 168, 0, 103),
            Ipv4Addr::new(255, 255, 255, 0),
        ))
        .unwrap();

        pcap(PcapConfig {
            filters: PcapFilters::default(),
            capture: PcapCapturePoints::All,
            output: File::create("bin/c.pcap").unwrap(),
        })
        .unwrap();

        spawn(
            BgpDeamon::new(3000, Ipv4Addr::new(192, 168, 0, 103))
                .add_neighbor(Ipv4Addr::new(192, 168, 0, 102), 2000, "link-b")
                .add_neighbor(Ipv4Addr::new(192, 168, 0, 104), 3000, "link-d")
                .add_nlri(Nlri::new(Ipv4Addr::new(30, 3, 1, 0), 16))
                .deploy(),
        );
    }

    async fn at_sim_end(&mut self) {
        for line in route().unwrap() {
            tracing::info!("{line}")
        }
    }
}

struct D;
#[async_trait::async_trait]
impl AsyncModule for D {
    fn new() -> Self {
        Self
    }

    async fn at_sim_start(&mut self, _: usize) {
        add_interface(Interface::ethv4(
            NetworkDevice::eth(),
            Ipv4Addr::new(192, 168, 0, 104),
        ))
        .unwrap();

        pcap(PcapConfig {
            filters: PcapFilters::default(),
            capture: PcapCapturePoints::All,
            output: File::create("bin/d.pcap").unwrap(),
        })
        .unwrap();

        spawn(
            BgpDeamon::new(3000, Ipv4Addr::new(192, 168, 0, 104))
                .add_neighbor(Ipv4Addr::new(192, 168, 0, 103), 3000, "en0")
                .add_nlri(Nlri::new(Ipv4Addr::new(40, 3, 1, 0), 16))
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

    des::tracing::Subscriber::default()
        .with_max_level(tracing::metadata::LevelFilter::TRACE)
        .init()
        .unwrap();

    let app = NetworkApplication::new(
        NdlApplication::new("bin/pkt.ndl", registry![A, B, C, D, Main]).unwrap(),
    );
    let rt = Builder::seeded(123)
        .max_time(1000.0.into())
        .max_itr(100)
        .build(app);

    let _ = rt.run();
}
