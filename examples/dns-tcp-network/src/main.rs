use std::fs::File;

use des::{prelude::*, registry, time::sleep, tracing::Subscriber};
use inet::{
    dns::lookup_host,
    interface::{add_interface, Interface, NetworkDevice},
    routing::{set_default_gateway, RoutingInformation},
    types::ip::IpMask,
    utils::LinkLayerSwitch,
    TcpListener, TcpStream,
};
use inet_dns::DNSNameserver;
use inet_pcap::{pcap, PcapCapturePoints, PcapConfig, PcapFilters};
use inet_rip::RipRoutingDeamon;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    spawn,
};

struct Client;
#[async_trait::async_trait]
impl AsyncModule for Client {
    fn new() -> Self {
        Self
    }
    async fn at_sim_start(&mut self, stage: usize) {
        if stage == 0 {
            return;
        }
        node_like_setup();

        spawn(async move {
            let mut server = DNSNameserver::client(par("addr").unwrap().parse().unwrap());

            server.allow_recursive_for(IpMask::catch_all_v4());
            server.launch().await.unwrap();
        });

        // if module_path().as_str() == "a1.node[0]" {
        spawn(async move {
            sleep(Duration::from_secs(1)).await;

            for _ in 0..100 {
                let domain = DOMAINS[random::<usize>() % DOMAINS.len()];
                let mut stream = TcpStream::connect((domain, 80)).await.unwrap();
                stream.write_all(domain.as_bytes()).await.unwrap();
                let mut buf = [0; 64];
                let n = stream.read(&mut buf).await.unwrap();
                assert_eq!(n, 1);
                assert_eq!(buf[0], 42);
            }
        });
        // }
    }

    fn num_sim_start_stages(&self) -> usize {
        2
    }
}

const DOMAINS: [&str; 15] = [
    "www.example.org",
    "ftp.example.org",
    "info.example.org",
    "status.info.example.org",
    "stats.example.org",
    "www.tu-ilmenau.de",
    "prakinf.telematik.tu-ilmenau.de",
    "os.tu-ilmenau.de",
    "www.bund.de",
    "id.bund.de",
    "www.admin.org",
    "recovery.admin.org",
    "www.test.org",
    "ftp.test.org",
    "status.test.org",
];

struct Server;
#[async_trait::async_trait]
impl AsyncModule for Server {
    fn new() -> Self {
        Self
    }

    async fn at_sim_start(&mut self, stage: usize) {
        if stage == 0 {
            return;
        }
        node_like_setup();

        spawn(async move {
            let mut server = DNSNameserver::client(par("addr").unwrap().parse().unwrap());

            server.allow_recursive_for(IpMask::catch_all_v4());
            server.launch().await.unwrap();
        });

        spawn(async move {
            let addr = par("addr").unwrap().parse::<Ipv4Addr>().unwrap();
            let list = TcpListener::bind("0.0.0.0:80").await.unwrap();
            loop {
                let accept = list.accept().await.unwrap();
                spawn(async move {
                    let (mut stream, from) = accept;

                    let mut buf = [0; 512];
                    let n = stream.read(&mut buf).await.unwrap();
                    let s = String::from_utf8_lossy(&buf[..n]);
                    let lookup = lookup_host((s.to_string(), 80))
                        .await
                        .unwrap()
                        .next()
                        .unwrap();
                    assert_eq!(lookup.ip(), addr);
                    stream.write_all(&[42]).await.unwrap();

                    tracing::trace!("responded to new stream from {from:?} known as {s}");
                });
            }
        });
    }

    fn num_sim_start_stages(&self) -> usize {
        2
    }
}

struct Dns;
#[async_trait::async_trait]
impl AsyncModule for Dns {
    fn new() -> Self {
        Self
    }

    async fn at_sim_start(&mut self, stage: usize) {
        if stage == 0 {
            return;
        }
        node_like_setup();

        let zone = par("zone").unwrap().into_inner();
        let domain_name = par("domain").unwrap().into_inner();

        tokio::spawn(async move {
            let mut dns = DNSNameserver::from_zonefile(&zone, "zonefiles", domain_name).unwrap();
            if zone == "." {
                dns.declare_root_ns();
            }
            dns.launch().await.unwrap();
        });
    }

    fn num_sim_start_stages(&self) -> usize {
        2
    }
}

fn node_like_setup() {
    let addr = par("addr").unwrap().parse::<Ipv4Addr>().unwrap();
    let mask = par("mask").unwrap().parse::<Ipv4Addr>().unwrap();
    let gateway = par("gateway").unwrap().parse::<Ipv4Addr>().unwrap();

    add_interface(Interface::loopback()).unwrap();

    add_interface(Interface::ethv4_named(
        "en0",
        NetworkDevice::eth(),
        addr,
        mask,
    ))
    .unwrap();
    set_default_gateway(gateway).unwrap();

    pcap(PcapConfig {
        capture: PcapCapturePoints::All,
        filters: PcapFilters::default(),
        output: std::fs::File::create(format!("results/{}.pcap", module_path())).unwrap(),
    })
    .unwrap();
}

struct Router;
#[async_trait::async_trait]
impl AsyncModule for Router {
    fn new() -> Self {
        Self
    }

    async fn at_sim_start(&mut self, stage: usize) {
        if stage == 0 {
            return;
        }

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
                output: File::create(format!("results/{}.pcap", module_path())).unwrap(),
            })
            .unwrap();
        }

        spawn(async move {
            sleep(Duration::from_secs_f64(random::<f64>())).await;
            let router = RipRoutingDeamon::lan_attached(addr, mask, lan, Default::default());
            router.deploy().await;
        });
    }

    fn num_sim_start_stages(&self) -> usize {
        2
    }

    // async fn at_sim_end(&mut self) {
    //     for line in inet::routing::route().unwrap() {
    //         tracing::info!("{}", line);
    //     }
    // }
}

struct LAN;
impl Module for LAN {
    fn new() -> Self {
        Self
    }

    fn at_sim_start(&mut self, _: usize) {
        let role = par("role").unwrap().into_inner();
        tracing::info!("Acting as {} network", role);

        let addr = par("addr").unwrap().parse::<Ipv4Addr>().unwrap();
        let mask = par("mask").unwrap().parse::<Ipv4Addr>().unwrap();

        // forward information to router
        let raddr = Ipv4Addr::from(u32::from(addr) + 1);
        let router = module_path().appended("router");
        par_for("addr", &router).set(raddr).unwrap();
        par_for("mask", &router).set(mask).unwrap();

        for i in 0..5 {
            let naddr = Ipv4Addr::from(u32::from(addr) + 101 + i);
            let node = module_path().appended(format!("node[{i}]"));
            par_for("addr", &node).set(naddr).unwrap();
            par_for("mask", &node).set(mask).unwrap();
            par_for("gateway", &node).set(raddr).unwrap();
        }
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

    Subscriber::default().init().unwrap();

    type Switch = LinkLayerSwitch;

    let app = NdlApplication::new(
        "main.ndl",
        registry![Dns, Client, Server, Router, Switch, LAN, Main],
    )
    .map_err(|e| println!("{e}"))
    .unwrap();
    let mut app = NetworkApplication::new(app);
    app.include_par_file("main.par");
    let rt = Builder::seeded(123).max_time(200.0.into()).build(app);
    let _app = rt.run().into_app();
    // app.globals()
    //     .topology
    //     .borrow()
    //     .write_to_svg("results/graph.svg")
    //     .unwrap();
}
