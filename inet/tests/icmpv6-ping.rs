use std::{
    io::{self, ErrorKind},
    net::Ipv6Addr,
    time::Duration,
};

use des::{net::globals, prelude::Message, runtime::RuntimeError, time::sleep};
use inet::{
    IOPlugin,
    env::RoutingPort,
    interface::{InterfaceDef, NetworkDevice},
    ioctx,
    ipv6::{self, util::setup_router},
    test_util::SimpleSim,
};
use serial_test::serial;
use tokio::sync::mpsc::Receiver;

async fn alice_success(_rx: Receiver<Message>) -> io::Result<()> {
    ioctx().add_interface(InterfaceDef::ethv6_autocfg(NetworkDevice::eth()))?;

    sleep(Duration::from_secs(10)).await;

    let addr = globals()
        .get(&"bob".into())
        .unwrap()
        .as_ref::<IOPlugin>()
        .handle()
        .get_interface("en0")?
        .status()
        .addrs
        .v6
        .unicast[0]
        .addr;
    let pinger = ipv6::icmp::ping::ping(addr).await?;
    tracing::info!("pinger done {pinger:?}");

    Ok(())
}

async fn alice_failure(_rx: Receiver<Message>) -> io::Result<()> {
    ioctx().add_interface(InterfaceDef::ethv6_autocfg(NetworkDevice::eth()))?;

    sleep(Duration::from_secs(10)).await;

    let err = ipv6::icmp::ping::ping(
        "2003:c1:e719:1234:88d5:1cff:0000:0000"
            .parse::<Ipv6Addr>()
            .unwrap(),
    )
    .await
    .unwrap_err();

    assert_eq!(
        err.kind(),
        ErrorKind::ConnectionRefused,
        "invalid error: {err}"
    );

    Ok(())
}

async fn bob(_rx: Receiver<Message>) -> io::Result<()> {
    ioctx().add_interface(InterfaceDef::ethv6_autocfg(NetworkDevice::eth()))?;
    sleep(Duration::from_secs(5)).await;
    tracing::info!("published en0");
    ioctx().get_interface("en0")?.status().publish();
    Ok(())
}

async fn router(_rx: Receiver<Message>) -> io::Result<()> {
    setup_router(
        "fe80::1111:2222".parse().unwrap(),
        RoutingPort::collect(),
        vec![
            "2003:c1:e719:8fff::/64".parse().unwrap(),
            "2003:c1:e719:1234::/64".parse().unwrap(),
        ],
    )
}

#[test]
#[serial]
fn v2_icmpv6_ping_success() -> Result<(), RuntimeError> {
    // des::tracing::init();

    let mut sim = SimpleSim::default();
    sim.raw("alice", alice_success);
    sim.raw("bob", bob);
    sim.raw("router", router);

    sim.run()
}

#[test]
#[serial]
fn v2_icmpv6_ping_failure() -> Result<(), RuntimeError> {
    // des::tracing::init();

    let mut sim = SimpleSim::default();
    sim.raw("alice", alice_failure);
    sim.raw("bob", bob);
    sim.raw("router", router);

    sim.run()
}
