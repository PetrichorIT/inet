use std::{fs::File, io::Error, net::Ipv6Addr, time::Duration};

use bytes_io::ToBytes;
use des::net::module::Module;

use inet::{
    UdpSocket,
    env::RoutingPort,
    interface::{InterfaceDef, NetworkDevice},
    ioctx,
    ipv6::{
        socket::RawV6Socket,
        util::{ping::ping, setup_router},
    },
    utils::SimpleSim,
};
use inet_pcap::pcap;
use types::{
    icmpv6::{IcmpV6MulticastListenerMessage, IcmpV6Packet, PROTO_ICMPV6},
    ip::Ipv6AddrExt,
};

#[derive(Default)]
struct HostAlice;

impl Module for HostAlice {
    fn at_sim_start(&mut self, _stage: usize) {
        pcap(File::create("out/ipv6_icmp_stack_alice.pcap").unwrap()).unwrap();

        ioctx()
            .add_interface(InterfaceDef::ethv6_autocfg(NetworkDevice::eth()))
            .unwrap();

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
        pcap(File::create("out/ipv6_icmp_stack_bob.pcap").unwrap()).unwrap();

        ioctx()
            .add_interface(InterfaceDef::ethv6_autocfg(NetworkDevice::eth()))
            .unwrap();

        tokio::spawn(async move {
            let udp = UdpSocket::bind(":::4000").await?;
            let mut buf = [0; 1024];
            let (n, from) = udp.recv_from(&mut buf).await?;
            tracing::info!(
                "response {:?} from {from:?}",
                String::from_utf8_lossy(&buf[..n]),
            );
            udp.send_to(b"Hello back", from).await?;

            let mut ipsock = RawV6Socket::new(PROTO_ICMPV6)?;
            ipsock.connect(Ipv6Addr::MULTICAST_ALL_NODES)?;
            // Ipv6Addr::MULTICAST_ALL_NODES
            let msg = IcmpV6Packet::MulticastListenerQuery(IcmpV6MulticastListenerMessage {
                maximum_response_delay: Duration::from_secs(1),
                multicast_addr: Ipv6Addr::UNSPECIFIED,
            });
            ipsock.try_send(&msg.write_to_bytes()?)?;

            Ok::<_, Error>(())
        });
    }
}

#[derive(Default)]
struct Router;

impl Module for Router {
    fn at_sim_start(&mut self, _stage: usize) {
        pcap(File::create("out/ipv6_icmp_stack_router.pcap").unwrap()).unwrap();

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

#[test]
fn ipv6_autcfg() -> Result<(), Box<dyn std::error::Error>> {
    // des::tracing::init();

    let mut sim = SimpleSim::default();
    sim.module("alice", HostAlice);
    sim.module("bob", HostBob);
    sim.module("router", Router);

    sim.run_max_time(10.0)?;
    Ok(())
}
