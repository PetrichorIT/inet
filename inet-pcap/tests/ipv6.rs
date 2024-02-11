use std::{fs::File, net::Ipv6Addr, time::Duration};

use des::{
    ndl::NdlApplication,
    net::module::{AsyncModule, Module},
    registry,
    runtime::Builder,
};
use inet::{
    interface::{add_interface, Interface, NetworkDevice},
    ipv6::{icmp::ping::ping, util::setup_router},
    routing::RoutingPort,
    utils, UdpSocket,
};
use inet_pcap::{pcap, PcapCapturePoints, PcapConfig, PcapFilters};

#[macro_use]
mod common;

struct HostAlice;
impl_build_named!(HostAlice);

impl AsyncModule for HostAlice {
    fn new() -> Self {
        Self
    }

    async fn at_sim_start(&mut self, _stage: usize) {
        pcap(PcapConfig {
            filters: PcapFilters::default(),
            capture: PcapCapturePoints::All,
            output: File::create("out/ipv6_icmp_stack_alice.pcap").unwrap(),
        })
        .unwrap();

        add_interface(Interface::ethv6_autocfg(NetworkDevice::eth())).unwrap();

        tokio::spawn(async move {
            des::time::sleep(Duration::from_secs(1)).await;

            let udp = UdpSocket::bind("2003:c1:e719:1234:ac1c:f4ff:fe85:879a:2000")
                .await
                .unwrap();
            udp.send_to(b"Hello world", "2003:c1:e719:1234:fc85:8aff:fed5:1c9d:4000")
                .await
                .unwrap();

            let mut buf = [0; 1024];
            let (n, from) = udp.recv_from(&mut buf).await.unwrap();
            tracing::info!(
                "response {:?} from {from:?}",
                String::from_utf8_lossy(&buf[..n]),
            );

            let p = ping(
                "2003:c1:e719:1234:fc85:8aff:fed5:1c9d"
                    .parse::<Ipv6Addr>()
                    .unwrap(),
            )
            .await
            .unwrap();
            tracing::info!("ping := {p}")
        });
    }
}

struct HostBob;
impl_build_named!(HostBob);

impl AsyncModule for HostBob {
    fn new() -> Self {
        Self
    }

    async fn at_sim_start(&mut self, _stage: usize) {
        pcap(PcapConfig {
            filters: PcapFilters::default(),
            capture: PcapCapturePoints::All,
            output: File::create("out/ipv6_icmp_stack_bob.pcap").unwrap(),
        })
        .unwrap();

        add_interface(Interface::ethv6_autocfg(NetworkDevice::eth())).unwrap();

        tokio::spawn(async move {
            let udp = UdpSocket::bind(":::4000").await.unwrap();
            let mut buf = [0; 1024];
            let (n, from) = udp.recv_from(&mut buf).await.unwrap();
            tracing::info!(
                "response {:?} from {from:?}",
                String::from_utf8_lossy(&buf[..n]),
            );
            udp.send_to(b"Hello back", from).await.unwrap();
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
        pcap(PcapConfig {
            filters: PcapFilters::default(),
            capture: PcapCapturePoints::All,
            output: File::create("out/ipv6_icmp_stack_router.pcap").unwrap(),
        })
        .unwrap();

        setup_router(
            "fe80::1111:2222".parse().unwrap(),
            RoutingPort::collect(),
            vec![
                "2003:c1:e719:8fff::/64".parse().unwrap(),
                "2003:c1:e719:1234::/64".parse().unwrap(),
            ],
        )
        .unwrap();

        tokio::spawn(async move {
            let udp = UdpSocket::bind(":::4000").await.unwrap();
            let mut buf = [0; 1024];
            let (n, from) = udp.recv_from(&mut buf).await.unwrap();
            tracing::info!(
                "received {:?} from {from:?}",
                String::from_utf8_lossy(&buf[..n])
            );
        });
    }
}

type Switch = utils::LinkLayerSwitch;

struct Main;
impl_build_named!(Main);
impl Module for Main {
    fn new() -> Self {
        Main
    }
}

#[test]
fn ipv6_autcfg() {
    inet::init();
    // des::tracing::Subscriber::default().init().unwrap();

    let app = NdlApplication::new(
        "tests/ipv6.ndl",
        registry![Main, HostAlice, HostBob, Router, Switch],
    )
    .unwrap();

    let rt = Builder::seeded(123)
        // .max_itr(30)
        .max_time(10.0.into())
        .build(app.into_app());
    let _ = rt.run();
}
