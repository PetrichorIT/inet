use std::{fs::File, time::Duration};

use des::net::module::Module;
use inet::{
    env::RoutingPort,
    interface::{InterfaceDef, NetworkDevice},
    ioctx,
    ipv6::util::setup_router,
    tcp::{TcpListener, TcpStream},
    utils::SimpleSim,
};
use inet_pcap::pcap;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Default)]
struct HostAlice;

impl Module for HostAlice {
    fn at_sim_start(&mut self, _stage: usize) {
        pcap(File::create("out/ipv6_tcp_stack_alice.pcap").unwrap()).unwrap();

        ioctx()
            .add_interface(InterfaceDef::ethv6_autocfg(NetworkDevice::eth()))
            .unwrap();

        tokio::spawn(async move {
            des::time::sleep(Duration::from_secs(2)).await;

            let res = TcpStream::connect("2003:c1:e719:1234:88d5:1cff:fe9d:43e2:8000").await;
            tracing::info!("{res:?}");

            res.unwrap().write_all(b"Hello world").await.unwrap();
        });
    }
}

#[derive(Default)]
struct HostBob;

impl Module for HostBob {
    fn at_sim_start(&mut self, _stage: usize) {
        pcap(File::create("out/ipv6_tcp_stack_bob.pcap").unwrap()).unwrap();

        ioctx()
            .add_interface(InterfaceDef::ethv6_autocfg(NetworkDevice::eth()))
            .unwrap();

        tokio::spawn(async move {
            let list = TcpListener::bind(":::8000").await.unwrap();
            let (mut sock, addr) = list.accept().await.unwrap();
            tracing::info!("incoming connection from {addr}");

            let mut buf = [0; 128];
            let n = sock.read(&mut buf).await.unwrap();
            tracing::info!("received {:?}", String::from_utf8_lossy(&buf[..n]));
        });
    }
}

#[derive(Default)]
struct Router;

impl Module for Router {
    fn at_sim_start(&mut self, _stage: usize) {
        pcap(File::create("out/ipv6_tcp_stack_router.pcap").unwrap()).unwrap();

        setup_router(
            "fe80::1111:2222".parse().unwrap(),
            RoutingPort::collect(),
            vec![
                "2003:c1:e719:8fff::/64".parse().unwrap(),
                "2003:c1:e719:1234::/64".parse().unwrap(),
            ],
        )
        .unwrap();
    }
}

#[test]
fn ipv6_tcp() -> Result<(), des::net::Failure> {
    // des::tracing::init();

    let mut sim = SimpleSim::default();
    sim.module("alice", HostAlice);
    sim.module("bob", HostBob);
    sim.module("router", Router);

    sim.run_max_time(10.0)?;
    Ok(())
}
