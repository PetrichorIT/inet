use bytes_io::Bytes;
use des::{net::handlers::AsyncHandler, prelude::*, time::sleep};
use inet::{
    interface::{IfId, InterfaceDef, NetworkDevice},
    ioctx,
    ipv6::router,
    socket::RawIpSocket,
};
use serial_test::serial;
use types::{
    iface::MacAddress,
    ip::{IPV6_MINIMUM_MTU, IpPacket, Ipv6AddrExt, Ipv6Packet},
    udp::PROTO_UDP,
};

#[test]
#[serial]
fn icmp_drop_packet_too_big() -> Result<(), RuntimeError> {
    // des::tracing::init();

    let mut sim = Sim::new(()).with_stack(inet::init);
    sim.node(
        "alice",
        AsyncHandler::io(|_| async move {
            ioctx().add_interface(InterfaceDef::ethv6_autocfg(NetworkDevice::eth()))?;
            sleep(Duration::from_secs(2)).await;

            let raw = RawIpSocket::new_v6()?;
            raw.try_send(IpPacket::V6(Ipv6Packet {
                src: Ipv6Addr::UNSPECIFIED,
                dst: "2003:b:1::abcd:1234".parse().unwrap(),
                traffic_class: 0,
                flow_label: 0,
                proto: PROTO_UDP,
                hop_limit: 64,
                extension_headers: Vec::new(),
                content: Bytes::from(vec![12; 800]),
            }))?;

            sleep(Duration::from_secs(2)).await;
            raw.try_send(IpPacket::V6(Ipv6Packet {
                src: Ipv6Addr::UNSPECIFIED,
                dst: "2003:b:1::abcd:1234".parse().unwrap(),
                traffic_class: 0,
                flow_label: 0,
                proto: PROTO_UDP,
                hop_limit: 64,
                extension_headers: Vec::new(),
                content: Bytes::from(vec![12; 1300]),
            }))?;

            Ok(())
        }),
    );
    sim.node(
        "bob",
        AsyncHandler::io(|mut rx| async move {
            ioctx().add_interface(InterfaceDef::ethv6_autocfg(NetworkDevice::eth()))?;
            sleep(Duration::from_secs(2)).await;

            let msg = rx.recv().await.unwrap();
            let ip = msg.body.content::<Ipv6Packet>();
            assert_eq!(ip.proto, PROTO_UDP);
            assert!(SimTime::now().as_secs() < 4);

            Ok(())
        }),
    );

    sim.node(
        "transit",
        AsyncHandler::io(|_| async move {
            router::declare_router()?;

            router::add_routing_interface(
                "port-a",
                NetworkDevice::gate("port-a", 0).unwrap(),
                &["2003:a:1::1".parse().unwrap(), Ipv6Addr::LINK_LOCAL],
                true,
            )?;
            router::add_routing_prefix("port-a", "2003:a:1::/64".parse()?)?;

            router::add_routing_interface(
                "port-b",
                NetworkDevice::gate("port-b", 0)
                    .unwrap()
                    .with_mtu(IPV6_MINIMUM_MTU),
                &["2003:b:1::1".parse().unwrap(), Ipv6Addr::LINK_LOCAL],
                true,
            )?;
            router::add_routing_prefix("port-b", "2003:b:1::/64".parse()?)?;

            router::add_routing_entry(
                "2003:b:1::/64".parse()?,
                "2003:b:1::1".parse().unwrap(),
                "2003:a:1::1".parse().unwrap(),
            )?;

            router::add_solicitation_entry(
                "2003:b:1::1".parse().unwrap(),
                MacAddress::generate(),
                IfId::new("port-b"),
            )?;

            Ok(())
        }),
    );

    let p1 = sim.gate("alice", "port");
    let p1_t = sim.gate("transit", "port-a");
    let p2 = sim.gate("bob", "port");
    let p2_t = sim.gate("transit", "port-b");

    let metrics = DatarateChannelMetrics::new(
        8_000_000,
        Duration::from_millis(10),
        Duration::ZERO,
        ChannelDropBehaviour::Queue(None),
    );

    p1.connect_with(p1_t, Some(DatarateChannel::new(metrics)));
    p2.connect_with(p2_t, Some(DatarateChannel::new(metrics)));

    Builder::seeded(123)
        .max_time(5.0.into())
        .build(sim.freeze())
        .run()
        .map(|_| ())
}
