use std::fs::File;

use des::{prelude::*, registry, tokio::spawn};
use inet::{
    icmp::traceroute,
    interface::{add_interface, Interface, NetworkDevice},
    pcap::{pcap, PcapConfig},
    routing::{set_default_gateway, RoutingInformation},
};

struct Alice {}
#[async_trait::async_trait]
impl AsyncModule for Alice {
    fn new() -> Self {
        Self {}
    }

    async fn at_sim_start(&mut self, _: usize) {
        let addr = par("addr").unwrap().parse::<Ipv4Addr>().unwrap();
        let mask = par("mask").unwrap().parse::<Ipv4Addr>().unwrap();
        let gw = par("gateway").unwrap().parse::<Ipv4Addr>().unwrap();
        add_interface(Interface::ethv4_named(
            "en0",
            NetworkDevice::eth(),
            addr,
            mask,
        ))
        .unwrap();
        set_default_gateway(gw).unwrap();
        // Ready to go
        spawn(async move {});
    }
}

struct Bob {}
#[async_trait::async_trait]
impl AsyncModule for Bob {
    fn new() -> Self {
        Self {}
    }
    async fn at_sim_start(&mut self, _: usize) {
        let addr = par("addr").unwrap().parse::<Ipv4Addr>().unwrap();
        let mask = par("mask").unwrap().parse::<Ipv4Addr>().unwrap();
        let gw = par("gateway").unwrap().parse::<Ipv4Addr>().unwrap();
        add_interface(Interface::ethv4_named(
            "en0",
            NetworkDevice::eth(),
            addr,
            mask,
        ))
        .unwrap();
        set_default_gateway(gw).unwrap();
        // Ready to go
        spawn(async move {});
    }
}

struct Eve {}
#[async_trait::async_trait]
impl AsyncModule for Eve {
    fn new() -> Self {
        Self {}
    }
    async fn at_sim_start(&mut self, _: usize) {
        let addr = par("addr").unwrap().parse::<Ipv4Addr>().unwrap();
        let mask = par("mask").unwrap().parse::<Ipv4Addr>().unwrap();
        let gw = par("gateway").unwrap().parse::<Ipv4Addr>().unwrap();
        add_interface(Interface::ethv4_named(
            "en0",
            NetworkDevice::eth(),
            addr,
            mask,
        ))
        .unwrap();
        set_default_gateway(gw).unwrap();

        // Ready to go
        spawn(async move {
            // let p = inet::TcpStream::connect("200.1.0.101:80").await;
            // log::info!("{p:?}");

            log::info!("{:?}", traceroute(Ipv4Addr::new(200, 1, 0, 1)).await);

            // let p = ping("200.1.0.81".parse::<Ipv4Addr>().unwrap()).await;
            // log::info!("{p:?}");

            // let p = inet::TcpStream::connect("200.1.0.81:80").await;
            // log::info!("{p:?}");

            // // let arp entry time out
            // sleep(Duration::from_secs(60)).await;

            // let p = ping("200.1.0.81".parse::<Ipv4Addr>().unwrap()).await;
            // log::info!("{p:?}");
        });
    }
}

struct Main {}
#[async_trait::async_trait]
impl AsyncModule for Main {
    fn new() -> Self {
        Self {}
    }

    async fn at_sim_start(&mut self, _: usize) {
        pcap(
            PcapConfig {
                enable: true,
                capture: inet::pcap::PcapCapture::Both,
            },
            File::create("results/ping.pcap").unwrap(),
        )
        .unwrap();

        for port in RoutingInformation::collect().ports {
            let peer = port.output.path_end().unwrap().owner().path();
            let gw = par_for("gateway", &peer)
                .unwrap()
                .parse::<Ipv4Addr>()
                .unwrap();
            let mask = par_for("mask", &peer).unwrap().parse::<Ipv4Addr>().unwrap();

            add_interface(Interface::ethv4_named(
                format!("en{}", port.output.pos()),
                port.into(),
                gw,
                mask,
            ))
            .unwrap();
        }
    }
}

fn main() {
    inet::init();

    Logger::new()
        // .interal_max_log_level(log::LevelFilter::Trace)
        .set_logger();

    let app = NdlApplication::new("src/bin/ping.ndl", registry![Alice, Bob, Eve, Main])
        .map_err(|e| println!("{e}"))
        .unwrap();
    let mut app = NetworkApplication::new(app);
    app.include_par_file("src/bin/ping.par");
    let rt = Runtime::new_with(app, RuntimeOptions::seeded(123).max_itr(50));
    let _ = rt.run().unwrap();
}
