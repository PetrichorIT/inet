use std::{
    error::Error,
    io,
    net::{Ipv6Addr, SocketAddr},
    time::Duration,
};

use des::{
    ndl::NdlApplication,
    net::{
        module::{current, AsyncModule, Module},
        par, par_for,
    },
    registry,
    runtime::Builder,
};
use inet::{
    interface::{add_interface, Interface, NetworkDevice},
    ipv6::router,
    utils, UdpSocket,
};
use inet_types::ip::{Ipv6AddrExt, Ipv6Prefix};

#[macro_use]
mod common;

struct Host;
impl_build_named!(Host);
impl AsyncModule for Host {
    fn new() -> Self {
        Self
    }

    async fn at_sim_start(&mut self, _stage: usize) {
        add_interface(Interface::ethv6_autocfg(NetworkDevice::eth())).unwrap();
        tokio::spawn(async move {
            des::time::sleep(Duration::from_secs(1)).await;
            if current().path().as_str() == "net[0].host[0]" {
                let trg: SocketAddr = "[2003:1234:4242:0:24d9:f8ff:fe7c:4130]:8000"
                    .parse()
                    .unwrap();

                tracing::info!("inital query");
                let conn = UdpSocket::bind(":::0").await?;
                conn.send_to(b"Hello world!", trg).await?;
                let mut buf = [0; 128];
                let (n, src) = conn.recv_from(&mut buf).await?;
                assert_eq!(src, trg);
                assert_eq!("Hello back!", String::from_utf8_lossy(&buf[..n]));
                tracing::info!("done");
            }

            if current().path().as_str() == "net[1].host[1]" {
                let sock = UdpSocket::bind(":::8000").await?;
                let mut buf = [0; 128];
                loop {
                    let (n, src) = sock.recv_from(&mut buf).await?;
                    tracing::info!(
                        "received {n} bytes from {src}: {}",
                        String::from_utf8_lossy(&buf[..n])
                    );
                    sock.send_to(b"Hello back!", src).await?;
                }
            }

            Ok::<_, io::Error>(())
        });
    }
}

struct Router;
impl_build_named!(Router);
impl AsyncModule for Router {
    fn new() -> Self {
        Self
    }

    async fn at_sim_start(&mut self, _stage: usize) {
        let prefix: Ipv6Prefix = par("prefix").unwrap().parse().unwrap();
        let peering_addr: Ipv6Addr = par("peering_addr").unwrap().parse().unwrap();
        router::declare_router().unwrap();
        router::add_routing_prefix(prefix).unwrap();

        let lan = NetworkDevice::gate("lan", 0).unwrap();
        router::add_routing_interface(
            "eth-lan-0",
            lan,
            &[prefix.addr(), Ipv6Addr::LINK_LOCAL],
            true,
        )
        .unwrap();

        let wan = NetworkDevice::gate("wan", 0).unwrap();
        router::add_routing_interface(
            "eth-wan-0",
            wan,
            &[peering_addr, Ipv6Addr::LINK_LOCAL],
            true,
        )
        .unwrap();

        let peer = current()
            .gate("wan", 0)
            .unwrap()
            .path_end()
            .unwrap()
            .owner();
        let peers_prefix: Ipv6Prefix = par_for("prefix", peer.path()).unwrap().parse().unwrap();
        let peers_addr: Ipv6Addr = par_for("peering_addr", peer.path())
            .unwrap()
            .parse()
            .unwrap();

        router::add_routing_entry(peers_prefix, peers_addr, peering_addr).unwrap();
        router::add_routing_prefix(prefix).unwrap();
    }
}

struct LAN;
impl_build_named!(LAN);
impl Module for LAN {
    fn new() -> Self {
        Self
    }
}

type Switch = utils::LinkLayerSwitch;

struct Main;
impl_build_named!(Main);
impl Module for Main {
    fn new() -> Self {
        Self
    }
}

#[test]
fn ipv6_two_nets() -> Result<(), Box<dyn Error>> {
    inet::init();
    // des::tracing::Subscriber::default().init().unwrap();

    let mut app = NdlApplication::new(
        "tests/ipv6_two_nets.ndl",
        registry![Host, Switch, Router, LAN, Main],
    )?
    .into_app();
    app.include_par_file("tests/ipv6_two_nets.par");
    let rt = Builder::seeded(123).max_time(10.0.into()).build(app);
    let _ = rt.run();

    Ok(())
}
