use std::{fs::File, net::Ipv6Addr, time::Duration};

use bytepack::ToBytestream;
use des::{
    net::{module::Module, Sim},
    registry,
    runtime::Builder,
};
use inet::{
    interface::{add_interface, Interface, NetworkDevice},
    ipv6::{icmp::ping::ping, util::setup_router},
    routing::RoutingPort,
    socket::RawIpSocket,
    utils, UdpSocket,
};
use inet_pcap::{pcap, PcapCapturePoints, PcapConfig, PcapFilters};
use inet_types::{
    icmpv6::{IcmpV6MulticastListenerMessage, IcmpV6Packet},
    ip::{IpPacket, Ipv6AddrExt, Ipv6Packet},
};

#[derive(Default)]
struct HostAlice;

impl Module for HostAlice {
    fn at_sim_start(&mut self, _stage: usize) {
        pcap(PcapConfig {
            filters: PcapFilters::default(),
            capture: PcapCapturePoints::All,
            output: File::create("out/ipv6_icmp_stack_alice.pcap").unwrap(),
        })
        .unwrap();

        add_interface(Interface::ethv6_autocfg(NetworkDevice::eth())).unwrap();

        tokio::spawn(async move {
            des::time::sleep(Duration::from_secs(2)).await;
            tracing::info!("lets go");
            let udp = UdpSocket::bind("2003:c1:e719:1234:ac1c:f4ff:fe85:879a:2000")
                .await
                .unwrap();
            udp.send_to(b"Hello world", "2003:c1:e719:1234:88d5:1cff:fe9d:43e2:4000")
                .await
                .unwrap();

            let mut buf = [0; 1024];
            let (n, from) = udp.recv_from(&mut buf).await.unwrap();
            tracing::info!(
                "response {:?} from {from:?}",
                String::from_utf8_lossy(&buf[..n]),
            );

            let p = ping(
                "2003:c1:e719:1234:88d5:1cff:fe9d:43e2"
                    .parse::<Ipv6Addr>()
                    .unwrap(),
            )
            .await
            .unwrap();
            tracing::info!("ping := {p}")
        });
    }
}

#[derive(Default)]
struct HostBob;

impl Module for HostBob {
    fn at_sim_start(&mut self, _stage: usize) {
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

            let ipsock = RawIpSocket::new_v6().unwrap();
            ipsock
                .try_send(IpPacket::V6(Ipv6Packet {
                    traffic_class: 0,
                    flow_label: 0,
                    next_header: 58,
                    hop_limit: 255,
                    src: Ipv6Addr::UNSPECIFIED,
                    dst: Ipv6Addr::MULTICAST_ALL_NODES,
                    content: {
                        let msg =
                            IcmpV6Packet::MulticastListenerQuery(IcmpV6MulticastListenerMessage {
                                maximum_response_delay: Duration::from_secs(1),
                                multicast_addr: Ipv6Addr::UNSPECIFIED,
                            });
                        msg.to_vec().unwrap()
                    },
                }))
                .unwrap();
        });
    }
}

#[derive(Default)]
struct Router;

impl Module for Router {
    fn at_sim_start(&mut self, _stage: usize) {
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

#[test]
fn ipv6_autcfg() {
    // des::tracing::init();

    let app = Sim::new(())
        .with_stack(inet::init)
        .with_ndl(
            "tests/ipv6.ndl",
            registry![HostAlice, HostBob, Router, Switch, else _],
        )
        .unwrap();

    let rt = Builder::seeded(123)
        // .max_itr(30)
        .max_time(10.0.into())
        .build(app);
    let _ = rt.run();
}
