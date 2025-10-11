use des::{
    net::{globals, handlers::AsyncHandler},
    prelude::*,
    time::sleep,
};
use inet::{
    interface::{InterfaceDef, NetworkDevice},
    ipv6::router,
};
use inet::{
    ioctx,
    tcp::{TcpListener, TcpStream},
};
use serial_test::serial;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use types::ip::{IPV6_MINIMUM_MTU, Ipv6AddrExt};

#[test]
#[serial]
fn test() -> Result<(), RuntimeError> {
    // des::tracing::init();

    let mut sim = Sim::new(()).with_stack(inet::init);
    sim.node(
        "alice",
        AsyncHandler::io(|_| async move {
            ioctx().add_interface(InterfaceDef::ethv6_autocfg(NetworkDevice::eth()))?;
            sleep(Duration::from_secs(3)).await;

            let target_addr: Ipv6Addr = globals()
                .get(&"bob".into())
                .unwrap()
                .prop("addr")
                .unwrap()
                .expect("must be there")
                .get();

            let mut tcp = TcpStream::connect((target_addr, 80)).await?;
            tcp.write_all(&[3; 4_000]).await?;

            sleep(Duration::from_secs(10)).await;

            Ok(())
        }),
    );
    sim.node(
        "bob",
        AsyncHandler::io(|_| async move {
            ioctx().add_interface(InterfaceDef::ethv6_autocfg(NetworkDevice::eth()))?;
            sleep(Duration::from_secs(2)).await;

            let addr = ioctx()
                .get_interface("en0")
                .unwrap()
                .status()
                .addrs
                .v6
                .unicast[1]
                .addr;
            current().prop("addr").unwrap().set(addr);

            let list = TcpListener::bind(":::80").await?;
            let (mut stream, _) = list.accept().await?;

            let mut acc = 0;
            loop {
                let n = stream.read(&mut [0; 10000]).await?;
                acc += n;
                if n == 0 {
                    break;
                }
            }

            assert_eq!(acc, 4_000);

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

            // router::add_routing_entry(
            //     "2003:b:1::/64".parse()?,
            //     "2003:b:1::1".parse().unwrap(),
            //     "2003:a:1::1".parse().unwrap(),
            // )?;

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
        .max_time(20.0.into())
        .build(sim.freeze())
        .run()
        .map(|_| ())
}
