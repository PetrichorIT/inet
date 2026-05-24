use std::{net::Ipv6Addr, time::Duration};

use bytes_io::{FromBytes, ToBytes};
use des::{
    Sim,
    prelude::{Module, current},
    time::sleep,
};
use des_ndl::{Ndl, registry};
use inet::{
    UdpSocket,
    interface::{InterfaceDef, NetworkDevice},
    ioctx,
    ipv6::router,
    types::ip::{Ipv6AddrExt, Ipv6Prefix},
    utils::LinkLayerSwitch,
};
use inet_rip::{DistanceVectorAddrFamily, RipConfig, RipNgPacket, RipRouter};
use serial_test::serial;

const NDL: &str = include_str!("simple-network.yml");
const PAR_V6: &str = include_str!("simple-network-v6.par.yml");

#[derive(Debug, Default)]
struct Client;
impl Module for Client {
    fn at_sim_start(&mut self, _stage: usize) {
        // add_interface(InterfaceDef::ethv6_autocfg(NetworkDevice::eth())).unwrap();
    }
}

#[derive(Debug, Default)]
struct Server;
impl Module for Server {
    fn at_sim_start(&mut self, _stage: usize) {
        // add_interface(InterfaceDef::ethv6_autocfg(NetworkDevice::eth())).unwrap();
    }
}

#[derive(Debug, Default)]
struct Router;
impl Module for Router {
    fn at_sim_start(&mut self, _stage: usize) {
        router::declare_router().unwrap();
        ioctx().add_interface(InterfaceDef::loopback()).unwrap();

        let prefix = current()
            .parent()
            .unwrap()
            .prop::<Ipv6Prefix>("prefix")
            .unwrap()
            .expect("no value")
            .get();
        let addr = Ipv6Addr::from(u128::from(prefix.addr()) + 1);

        router::add_routing_interface("lan", NetworkDevice::gate("lan", 0).unwrap(), &[addr], true)
            .unwrap();
        router::add_routing_prefix("lan", prefix).unwrap();

        for i in 0..3 {
            let g = current().gate(("port", i)).unwrap();
            let ge = g.path_end().unwrap();

            if ge.path().as_str().contains("router") {
                let lesser = u16::from_str_radix(
                    (&g.path().as_str()[..2]).min(&ge.path().as_str()[..2]),
                    16,
                )
                .unwrap();
                let greater = u16::from_str_radix(
                    (&g.path().as_str()[..2]).max(&ge.path().as_str()[..2]),
                    16,
                )
                .unwrap();

                let is_lesser = g.path().as_str()[..2] < ge.path().as_str()[..2];

                let subnet = Ipv6Addr::new(0x2003, 0xcccc, greater, lesser, 0, 0, 0, 0);
                let binding = subnet | Ipv6Addr::from(if is_lesser { 1 } else { 2 });

                tracing::info!("active port {}->{} @ {binding}", g.path(), ge.path(),);

                router::add_routing_interface(
                    g.path().name(),
                    NetworkDevice::from_gate(g.clone()),
                    &[binding, Ipv6Addr::LINK_LOCAL],
                    false,
                )
                .unwrap();
                router::add_routing_prefix(g.path().name(), Ipv6Prefix::new(subnet, 64)).unwrap();
            }
        }

        tokio::spawn(RipRouter::new(prefix, addr, RipConfig::default()).run());

        tokio::spawn(async move {
            sleep(Duration::from_secs(9)).await;

            let sock = UdpSocket::bind(":::0").await.unwrap();
            sock.send_to(
                &Ipv6Addr::make_full_dvs_req(
                    Ipv6Addr::UNSPECIFIED,
                    Ipv6Prefix::new(Ipv6Addr::UNSPECIFIED, 0),
                )
                .write_to_bytes()
                .unwrap(),
                "::1:512",
            )
            .await
            .unwrap();

            let mut buf = [0; 1500];
            let (n, _) = sock.recv_from(&mut buf).await.unwrap();
            let packet = RipNgPacket::peek_from(&buf[..n]).unwrap();
            tracing::info!("final: \n{packet:?}");
        });
    }
}

type Switch = LinkLayerSwitch;

#[test]
#[serial]
fn run() -> Result<(), Box<dyn std::error::Error>> {
    des::tracing::init();

    let mut sim = Sim::new(()).with_stack(inet::init);
    sim.include_cfg(PAR_V6);
    let ndl = serde_yml::from_str(NDL)?;
    sim.node(
        "",
        Ndl::new(&mut registry![Client, Server, Switch, Router,else _], &ndl)?,
    )?;

    let _ = sim
        .seeded(123)
        .max_time(10.0.into())
        .build()
        .run()
        .into_result()?;
    Ok(())
}
