use std::{fs::File, io::Error};

use des::{prelude::*, registry, time::sleep};
use inet::{
    interface::{add_interface, Interface, NetworkDevice},
    routing::{add_routing_entry, set_default_gateway, RoutingInformation},
    utils::LinkLayerSwitch,
};
use inet_bgp::{pkt::Nlri, BgpDeamon, BgpDeamonManagmentEvent};
use inet_pcap::{pcap, PcapCapturePoints, PcapConfig, PcapFilters};
use inet_rip::RipRoutingDeamon;
use tokio::spawn;

struct NetA;
impl Module for NetA {
    fn new() -> Self {
        Self
    }
}

struct BgpA;

impl AsyncModule for BgpA {
    fn new() -> Self {
        Self
    }

    async fn at_sim_start(&mut self, _: usize) {
        add_interface(Interface::ethv4_named(
            "en0",
            NetworkDevice::eth(),
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(255, 255, 0, 0),
        ))
        .unwrap();

        add_routing_entry(
            Ipv4Addr::new(10, 0, 2, 0),
            Ipv4Addr::new(255, 255, 255, 0),
            Ipv4Addr::new(10, 0, 2, 100),
            "en0",
        )
        .unwrap();

        add_interface(Interface::ethv4_named(
            "link-b",
            NetworkDevice::eth_select(|r| r.input.name().starts_with("b")),
            Ipv4Addr::new(192, 168, 0, 101),
            Ipv4Addr::new(255, 255, 255, 0),
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
                .add_neighbor(Ipv4Addr::new(192, 168, 0, 102), 2000, "link-b")
                .lan_iface("en0")
                .add_nlri(Nlri::new(Ipv4Addr::new(10, 0, 0, 0), 16))
                .deploy(),
        );
    }
}

// ffffffffffffffffffffffffffffffff 00 1d 0104 fe09 00b4c 0a8006500
// ffffffffffffffffffffffffffffffff 00 1d 0104 fe09 00b4c 0a8000f00

struct B;

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

        spawn(async {
            let tx = BgpDeamon::new(3000, Ipv4Addr::new(192, 168, 0, 103))
                .add_neighbor(Ipv4Addr::new(192, 168, 0, 102), 2000, "link-b")
                .add_neighbor(Ipv4Addr::new(192, 168, 0, 104), 3000, "link-d")
                .add_nlri(Nlri::new(Ipv4Addr::new(30, 3, 1, 0), 16))
                .deploy()
                .await?;

            sleep(Duration::from_secs(300)).await;
            tx.send(BgpDeamonManagmentEvent::StopPeering(Ipv4Addr::new(
                192, 168, 0, 104,
            )))
            .await
            .unwrap();

            Ok::<(), Error>(())
        });
    }
}

struct D;

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

struct Node;

impl AsyncModule for Node {
    fn new() -> Self {
        Self
    }

    async fn at_sim_start(&mut self, _: usize) {
        add_interface(Interface::ethv4(
            NetworkDevice::eth(),
            par("addr").unwrap().parse().unwrap(),
        ))
        .unwrap();

        set_default_gateway(par("gw").unwrap().parse::<Ipv4Addr>().unwrap()).unwrap();

        spawn(async move {
            // if module_name() == "node[0]" {
            //     sleep(Duration::from_secs(5)).await;
            //     tracing::info!("SENDING PKT");

            //     let tcp = TcpStream::connect("40.3.1.2:80").await;
            //     tracing::error!("{tcp:?}");
            // }
            Ok::<(), Error>(())
        });
    }
}

struct Router;

impl AsyncModule for Router {
    fn new() -> Self {
        Self
    }

    async fn at_sim_start(&mut self, _: usize) {
        let addr = par("addr").unwrap().parse::<Ipv4Addr>().unwrap();
        let mask = par("mask").unwrap().parse::<Ipv4Addr>().unwrap();

        let ports = RoutingInformation::collect();
        let lan = ports
            .ports
            .iter()
            .find(|p| p.output.name() == "lan_out")
            .cloned()
            .unwrap();

        if par("pcap").unwrap().parse::<bool>().unwrap() {
            pcap(PcapConfig {
                filters: PcapFilters::default(),
                capture: PcapCapturePoints::All,
                output: File::create(format!("bin/{}.pcap", current().path())).unwrap(),
            })
            .unwrap();
        }

        spawn(async move {
            sleep(Duration::from_secs_f64(random::<f64>())).await;
            let router = RipRoutingDeamon::lan_attached(addr, mask, lan, Default::default());
            router.deploy().await;
        });

        spawn(async move {
            sleep(Duration::from_secs(1)).await;
            set_default_gateway("10.0.0.1".parse::<Ipv4Addr>().unwrap()).unwrap();
        });
    }
}

fn main() {
    inet::init();

    type Switch = LinkLayerSwitch;

    des::tracing::Subscriber::default()
        .with_max_level(tracing::metadata::LevelFilter::TRACE)
        .init()
        .unwrap();

    let mut app = NetworkApplication::new(
        NdlApplication::new(
            "bin/bgp.ndl",
            registry![BgpA, NetA, Switch, Node, Router, B, C, D, Main],
        )
        .unwrap(),
    );
    app.include_par_file("bin/bgp.par");
    let rt = Builder::seeded(123)
        .max_time(1000.0.into())
        .max_itr(100)
        .build(app);

    let _ = rt.run();
}
