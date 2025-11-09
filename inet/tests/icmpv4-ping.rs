use std::{
    io::{self, ErrorKind},
    net::Ipv4Addr,
    time::Duration,
};

use des::{net::globals, prelude::Message, runtime::RuntimeError, time::sleep};
use inet::{
    IOPlugin,
    interface::{InterfaceDef, NetworkDevice},
    ioctx, ipv4,
    utils::SimpleSim,
};
use serial_test::serial;
use tokio::sync::mpsc::Receiver;

async fn alice_success(_rx: Receiver<Message>) -> io::Result<()> {
    ioctx().add_interface(
        InterfaceDef::new("en0", NetworkDevice::eth()).ip("192.168.2.101".parse().unwrap()),
    )?;
    sleep(Duration::from_secs(10)).await;

    let addr = globals()
        .get(&"bob".into())
        .unwrap()
        .as_ref::<IOPlugin>()
        .handle()
        .get_interface("en0")?
        .status()
        .addrs
        .v4
        .unicast[0]
        .addr;
    let pinger = ipv4::util::ping::ping(addr).await?;
    tracing::info!("pinger done {pinger:?}");

    Ok(())
}

async fn alice_failure(_rx: Receiver<Message>) -> io::Result<()> {
    ioctx().add_interface(
        InterfaceDef::new("en0", NetworkDevice::eth()).ip("192.168.2.101".parse().unwrap()),
    )?;
    sleep(Duration::from_secs(10)).await;

    let err = ipv4::util::ping::ping("192.168.2.103".parse::<Ipv4Addr>().unwrap())
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
    ioctx().add_interface(
        InterfaceDef::new("en0", NetworkDevice::eth()).ip("192.168.2.102".parse().unwrap()),
    )?;
    sleep(Duration::from_secs(5)).await;
    tracing::info!("published en0");
    ioctx().get_interface("en0")?.status().publish();
    Ok(())
}

#[test]
#[serial]
fn icmpv4_ping_success() -> Result<(), RuntimeError> {
    // des::tracing::init();

    let mut sim = SimpleSim::default();
    sim.raw("alice", alice_success);
    sim.raw("bob", bob);

    sim.run()
}

#[test]
#[serial]
fn icmpv4_ping_failure() -> Result<(), RuntimeError> {
    // des::tracing::init();

    let mut sim = SimpleSim::default();
    sim.raw("alice", alice_failure);
    sim.raw("bob", bob);

    sim.run()
}
