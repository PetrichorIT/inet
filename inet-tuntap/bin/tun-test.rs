use std::{io, time::Duration};

use des::{prelude::Message, runtime::des::Error, time::sleep};
use inet::{
    env::RoutingPort,
    interface::{InterfaceDef, NetworkDevice},
    ioctx,
    ipv6::util::setup_router,
    utils::SimpleSim,
};
use inet_tuntap::ptun;
use tokio::sync::mpsc::Receiver;

async fn router(_: Receiver<Message>) -> io::Result<()> {
    setup_router(
        "fe80::1111:2222".parse().unwrap(),
        RoutingPort::collect(),
        vec![
            "2003:c1:e719:8fff::/64".parse().unwrap(),
            "2003:c1:e719:1234::/64".parse().unwrap(),
        ],
    )
}

async fn alice(_: Receiver<Message>) -> io::Result<()> {
    ptun("utun8")?;

    let handle = ioctx().add_interface(InterfaceDef::new("en0", NetworkDevice::eth()).v6())?;
    sleep(Duration::from_secs(5)).await;
    assert_eq!(handle.status().addrs.v6.unicast.len(), 3);
    Ok(())
}

async fn bob(_: Receiver<Message>) -> io::Result<()> {
    let handle = ioctx().add_interface(InterfaceDef::new("en0", NetworkDevice::eth()).v6())?;
    sleep(Duration::from_secs(5)).await;
    assert_eq!(handle.status().addrs.v6.unicast.len(), 3);
    Ok(())
}

fn main() -> Result<(), des::Failure> {
    // des::tracing::init();

    let mut sim = SimpleSim::default();

    sim.raw("router", router);
    sim.raw("alice", alice);
    sim.raw("bob", bob);

    sim.run()
}
