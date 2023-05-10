use des::{
    prelude::*,
    registry,
    tokio::{spawn, time::sleep},
};
use inet::{
    interface::{add_interface, Interface, NetworkDevice},
    pcap::{pcap, PcapConfig},
    routing::{rip::RoutingDeamon, set_default_gateway, RoutingInformation},
    utils::LinkLayerSwitch,
    TcpListener, TcpStream,
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
            if module_path().as_str() == "a1.node[0]" {
                pcap(
                    PcapConfig {
                        enable: true,
                        capture: inet::pcap::PcapCapture::Both,
                    },
                    std::fs::File::create("results/client.pcap").unwrap(),
                )
                .unwrap();

                sleep(Duration::from_secs(5)).await;
                let sock = TcpStream::connect("190.32.100.103:80").await;
                log::info!("{sock:?}")
            }

            if module_path().as_str() == "d2.node[2]" {
                log::info!("building list");
                let lis = TcpListener::bind("0.0.0.0:80").await.unwrap();
                let r = lis.accept().await;
                log::info!("{r:?}");
            }
        });
    }

    fn num_sim_start_stages(&self) -> usize {
        2
    }
}

type Server = Client;
type Dns = Client;

// struct Server;
// impl Module for Server {
//     fn new() -> Self {
//         Self
//     }
//     fn at_sim_start(&mut self, stage: usize) {
//         if stage == 0 {
//             return;
//         }
//         node_like_setup()
//     }

//     fn num_sim_start_stages(&self) -> usize {
//         2
//     }
// }

// struct Dns;
// impl Module for Dns {
//     fn new() -> Self {
//         Self
//     }

//     fn at_sim_start(&mut self, stage: usize) {
//         if stage == 0 {
//             return;
//         }
//         node_like_setup()
//     }

//     fn num_sim_start_stages(&self) -> usize {
//         2
//     }
// }

fn node_like_setup() {
    let addr = par("addr").unwrap().parse::<Ipv4Addr>().unwrap();
    let mask = par("mask").unwrap().parse::<Ipv4Addr>().unwrap();
    let gateway = par("gateway").unwrap().parse::<Ipv4Addr>().unwrap();

    add_interface(Interface::ethv4_named(
        "en0",
        NetworkDevice::eth(),
        addr,
        mask,
    ))
    .unwrap();

    set_default_gateway(gateway).unwrap();
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

        pcap(
            PcapConfig {
                enable: par("pcap").unwrap().parse().unwrap(),
                capture: inet::pcap::PcapCapture::Both,
            },
            std::fs::File::create(format!("results/full/{}.pcap", module_path())).unwrap(),
        )
        .unwrap();

        spawn(async move {
            sleep(Duration::from_secs_f64(random::<f64>())).await;
            let router = RoutingDeamon::new(addr, mask, lan);
            router.deploy().await;
        });
    }

    fn num_sim_start_stages(&self) -> usize {
        2
    }

    // async fn at_sim_end(&mut self) {
    //     for line in inet::routing::route().unwrap() {
    //         log::info!("{}", line.str());
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
        log::info!("Acting as {} network", role);

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

    Logger::new()
        // .interal_max_log_level(log::LevelFilter::Trace)
        .set_logger();

    type Switch = LinkLayerSwitch;

    let app = NdlApplication::new(
        "src/bin/full/main.ndl",
        registry![Dns, Client, Server, Router, Switch, LAN, Main],
    )
    .map_err(|e| println!("{e}"))
    .unwrap();
    let mut app = NetworkApplication::new(app);
    app.include_par_file("src/bin/full/main.par");
    let rt = Runtime::new_with(app, RuntimeOptions::seeded(123).max_time(50.0.into()));
    let app = rt.run().into_app();
    app.globals()
        .topology
        .lock()
        .unwrap()
        .write_to_svg("results/graph.svg")
        .unwrap();
}
