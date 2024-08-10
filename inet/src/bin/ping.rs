use des::{prelude::*, registry};
use inet::{
    icmp::traceroute,
    interface::{add_interface, Interface, NetworkDevice},
    routing::{set_default_gateway, RoutingInformation},
};
use tokio::spawn;

#[derive(Default)]
struct Alice {}

impl Module for Alice {
    fn at_sim_start(&mut self, _: usize) {
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

#[derive(Default)]
struct Bob {}

impl Module for Bob {
    fn at_sim_start(&mut self, _: usize) {
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

#[derive(Default)]
struct Eve {}

impl Module for Eve {
    fn at_sim_start(&mut self, _: usize) {
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
            // tracing::info!("{p:?}");

            tracing::info!("{:?}", traceroute(Ipv4Addr::new(200, 1, 0, 1)).await);

            // let p = ping("200.1.0.81".parse::<Ipv4Addr>().unwrap()).await;
            // tracing::info!("{p:?}");

            // let p = inet::TcpStream::connect("200.1.0.81:80").await;
            // tracing::info!("{p:?}");

            // // let arp entry time out
            // sleep(Duration::from_secs(60)).await;

            // let p = ping("200.1.0.81".parse::<Ipv4Addr>().unwrap()).await;
            // tracing::info!("{p:?}");
        });
    }
}

#[derive(Default)]
struct Main {}

impl Module for Main {
    fn at_sim_start(&mut self, _: usize) {
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
    des::tracing::init();

    let mut app = Sim::new(())
        .with_stack(inet::init)
        .with_ndl("inet/src/bin/ping.ndl", registry![Alice, Bob, Eve, Main])
        .map_err(|e| println!("{e}"))
        .unwrap();
    app.include_par_file("inet/src/bin/ping.par").unwrap();
    let rt = Builder::seeded(123).max_itr(50).build(app);
    let _ = rt.run().unwrap();
}
