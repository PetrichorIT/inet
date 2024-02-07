use std::{net::Ipv6Addr, time::Duration};

use des::net::{
    module::{current, AsyncModule, Module},
    par, par_for, Topology,
};
use inet::{
    interface::{add_interface, Interface, InterfaceAddr, NetworkDevice},
    ipv6::router,
    routing::{declare_ipv6_router, Ipv6RouterConfig},
    UdpSocket,
};
use inet_types::{
    iface::MacAddress,
    ip::{Ipv6AddrExt, Ipv6Prefix},
};

#[macro_use]
mod common;

struct Host;
impl_build_named!(Host);
impl AsyncModule for Host {
    fn new() -> Self {
        Self
    }

    async fn at_sim_start(&mut self, _stage: usize) {
        tokio::spawn(async move {
            let secs = des::runtime::random::<f64>();
            des::time::sleep(Duration::from_secs_f64(secs)).await;
            add_interface(Interface::ethv6_autocfg(NetworkDevice::eth())).unwrap();
            des::time::sleep(Duration::from_secs(1)).await;

            if current().path().as_str() == "net[0].host[0]" {
                tracing::info!("initating query");
                let sock = UdpSocket::bind(":::0").await.unwrap();
                sock.send_to(
                    b"AAAABBBBCCCCDDDD",
                    "2003:abcd:4:0:287f:7bff:fea7:9b55:8000",
                )
                .await
                .unwrap();
            }

            // to 4.1
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
        let addr: Ipv6Addr = par("addr").unwrap().parse().unwrap();
        let prefix: Ipv6Prefix = par("prefix").unwrap().parse().unwrap();

        declare_ipv6_router(Ipv6RouterConfig {
            current_hop_limit: 255,
            managed: false,
            other_cfg: false,
            lifetime: Duration::from_secs(9000),
            reachable_time: Duration::from_secs(90),
            retransmit_time: Duration::from_secs(90),
            prefixes: vec![prefix],
        })
        .unwrap();

        // LAN interface
        let mut iface = Interface::ethv6_named(
            "eth-lan",
            NetworkDevice::eth_select(|p| p.name == "lan"),
            addr,
        );
        iface.flags.router = true;
        iface
            .addrs
            .add(InterfaceAddr::ipv6_link_local(iface.device.addr));
        add_interface(iface).unwrap();

        // WAN route probing
        let mut top = Topology::current();
        top.filter_nodes(|n| n.module.name() == "router");
        let map = top.dijkstra(current().path());

        let mut allready_assigned = Vec::new();
        for (k, v) in map {
            let local_idx = v.pos() as u128;
            let remote = v.path_end().unwrap();
            let remote_idx = remote.pos() as u128;
            let remote_prefix: Ipv6Prefix = par_for("prefix", remote.owner().path())
                .unwrap()
                .parse()
                .unwrap();

            if !allready_assigned.contains(&local_idx) {
                // create local iface with predicatable addrr
                let mut device = NetworkDevice::custom(v.clone(), v.clone());
                device.addr =
                    MacAddress::from([0, 0, 0, prefix.addr().octets()[5], 0, local_idx as u8]);

                let ip = device.addr.embed_into(Ipv6Addr::LINK_LOCAL);
                let mut iface = Interface::ethv6_named(format!("eth-{local_idx}"), device, ip);
                iface.flags.router = true;

                let ifid = iface.name.id();

                add_interface(iface).unwrap();
                allready_assigned.push(local_idx);

                tracing::debug!("assigned {ip} to {ifid}");
            }

            let hop_remote = MacAddress::from([
                0,
                0,
                0,
                remote_prefix.addr().octets()[5],
                0,
                remote_idx as u8,
            ])
            .embed_into(Ipv6Addr::LINK_LOCAL);

            let hop_local =
                MacAddress::from([0, 0, 0, prefix.addr().octets()[5], 0, local_idx as u8])
                    .embed_into(Ipv6Addr::LINK_LOCAL);
            let target_prefix = par_for("prefix", k).unwrap().parse().unwrap();

            tracing::info!("{:>15} = {} via {}", target_prefix, hop_remote, hop_local);
            router::add_routing_entry(target_prefix, hop_remote, hop_local).unwrap();
        }
    }
}

// type Switch = utils::LinkLayerSwitch;

struct LAN;
impl_build_named!(LAN);
impl Module for LAN {
    fn new() -> Self {
        Self
    }
}

struct Main;
impl_build_named!(Main);
impl Module for Main {
    fn new() -> Self {
        Self
    }
}

// #[test]
// fn traceroute_success() -> Result<(), Box<dyn Error>> {
//     inet::init();
//     des::tracing::Subscriber::default().init().unwrap();

//     let ndl = NdlApplication::new(
//         "tests/icmpv6_traceroute.ndl",
//         registry![Host, Switch, Router, LAN, Main],
//     )?;
//     let mut app = ndl.into_app();
//     app.include_par_file("tests/icmpv6_traceroute.par");
//     let rt = Builder::seeded(123).max_time(10.0.into()).build(app);
//     let _ = rt.run();

//     Ok(())
// }
