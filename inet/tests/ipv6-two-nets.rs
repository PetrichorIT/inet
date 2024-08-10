use std::{error::Error, io, net::Ipv6Addr, time::Duration};

use des::{
    net::{
        module::{current, Module},
        par, par_for, Sim,
    },
    registry,
    runtime::Builder,
};
use inet::{
    interface::{add_interface, interface_status, Interface, NetworkDevice},
    ipv6::router,
    utils, UdpSocket,
};
use inet_types::ip::{Ipv6AddrExt, Ipv6Prefix};

#[derive(Default)]
struct Host;

impl Module for Host {
    fn at_sim_start(&mut self, _stage: usize) {
        add_interface(Interface::ethv6_autocfg(NetworkDevice::eth())).unwrap();
        tokio::spawn(async move {
            des::time::sleep(Duration::from_secs(2)).await;
            interface_status("en0").unwrap().write_to_par().unwrap();

            if current().path().as_str() == "net[0].host[0]" {
                des::time::sleep(Duration::from_secs(1)).await;

                let trg: Ipv6Addr = par_for("en0:addrs", "net[1].host[1]")
                    .unwrap()
                    .split(',')
                    .collect::<Vec<_>>()[1]
                    .trim()
                    .parse()
                    .unwrap();

                tracing::info!("inital query to {trg}");
                let conn = UdpSocket::bind(":::0").await?;
                conn.send_to(b"Hello world!", (trg, 8000)).await?;
                let mut buf = [0; 128];
                let (n, src) = conn.recv_from(&mut buf).await?;
                assert_eq!(src.ip(), trg);
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

#[derive(Default)]
struct Router;

impl Module for Router {
    fn at_sim_start(&mut self, _stage: usize) {
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

type Switch = utils::LinkLayerSwitch;

#[test]
fn ipv6_two_nets() -> Result<(), Box<dyn Error>> {
    // des::tracing::init();

    let mut app = Sim::new(()).with_stack(inet::init).with_ndl(
        "tests/ipv6_two_nets.ndl",
        registry![Host, Switch, Router, else _],
    )?;
    app.include_par_file("tests/ipv6_two_nets.par").unwrap();
    let rt = Builder::seeded(123).max_time(10.0.into()).build(app);
    let _ = rt.run();

    Ok(())
}
