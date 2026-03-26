#![cfg(feature = "props")]
use std::{io, net::Ipv6Addr, time::Duration};

use des::{
    net::{
        Sim, globals,
        module::{Module, current},
    },
    runtime::Builder,
};
use des_ndl::{Ndl, registry};
use inet::{
    UdpSocket,
    interface::{InterfaceDef, InterfaceStatus, NetworkDevice},
    ioctx,
    ipv6::router,
    utils,
};
use types::ip::{Ipv6AddrExt, Ipv6Prefix};

#[derive(Default)]
struct Host;

impl Module for Host {
    fn at_sim_start(&mut self, _stage: usize) {
        ioctx()
            .add_interface(InterfaceDef::ethv6_autocfg(NetworkDevice::eth()))
            .unwrap();
        tokio::spawn(async move {
            des::time::sleep(Duration::from_secs(2)).await;
            ioctx().get_interface("en0").unwrap().status().publish();

            if current().path().as_str() == "net[0].host[0]" {
                des::time::sleep(Duration::from_secs(1)).await;

                println!(
                    "{:?}",
                    globals().get(&"net[1].host[1]").unwrap().props_keys()
                );

                let trg = globals()
                    .get(&"net[1].host[1]")
                    .unwrap()
                    .prop::<InterfaceStatus>("inet.iface.en0")
                    .unwrap()
                    .get()
                    .unwrap()
                    .addrs
                    .addrs()
                    .next()
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
        let prefix = current()
            .prop::<Ipv6Prefix>("prefix")
            .unwrap()
            .get()
            .unwrap();
        let peering_addr = current()
            .prop::<Ipv6Addr>("peering_addr")
            .unwrap()
            .get()
            .unwrap();
        router::declare_router().unwrap();

        let lan = NetworkDevice::gate("lan", 0).unwrap();
        router::add_routing_interface(
            "eth-lan-0",
            lan,
            &[prefix.addr(), Ipv6Addr::LINK_LOCAL],
            true,
        )
        .unwrap();
        router::add_routing_prefix("eth-lan-0", prefix).unwrap();

        let wan = NetworkDevice::gate("wan", 0).unwrap();
        router::add_routing_interface(
            "eth-wan-0",
            wan,
            &[peering_addr, Ipv6Addr::LINK_LOCAL],
            true,
        )
        .unwrap();

        let peer = current().gate("wan").unwrap().path_end().unwrap().owner();
        let peers_prefix = peer.prop::<Ipv6Prefix>("prefix").unwrap().get().unwrap();
        let peers_addr = peer
            .prop::<Ipv6Addr>("peering_addr")
            .unwrap()
            .get()
            .unwrap();

        router::add_routing_entry(peers_prefix, peers_addr, peering_addr).unwrap();
    }
}

type Switch = utils::LinkLayerSwitch;

#[test]
fn ipv6_two_nets() -> Result<(), Box<dyn std::error::Error>> {
    des::tracing::init();

    let mut sim = Sim::new(())
        .with_stack(inet::init)
        .with_cfg(include_str!("ipv6_two_nets.par.yml"));
    let def = serde_norway::from_str(include_str!("ipv6_two_nets.yml"))?;
    sim.node(
        "",
        Ndl::new(&mut registry![Host, Switch, Router, else _], &def)?,
    )?;

    let rt = Builder::seeded(123)
        .max_time(10.0.into())
        .build(sim.freeze());
    let _ = rt.run().as_result()?;
    Ok(())
}
