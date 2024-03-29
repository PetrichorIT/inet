use std::{error::Error, io::ErrorKind, net::Ipv6Addr, time::Duration};

use des::{
    net::{module::AsyncModule, par_for, Sim},
    registry,
    runtime::Builder,
};
use inet::{
    interface::{add_interface, interface_status, Interface, NetworkDevice},
    ipv6::{self, util::setup_router},
    routing::RoutingPort,
    utils,
};
use serial_test::serial;
use tokio::task::JoinHandle;

#[derive(Default)]
struct AliceSuccess {
    handles: Vec<JoinHandle<()>>,
}

impl AsyncModule for AliceSuccess {
    async fn at_sim_start(&mut self, _stage: usize) {
        // add_interface(Interface::loopback()).unwrap();
        add_interface(Interface::ethv6_autocfg(NetworkDevice::eth())).unwrap();
        self.handles.push(tokio::spawn(async move {
            des::time::sleep(Duration::from_secs(10)).await;
            let _ping = ipv6::icmp::ping::ping(
                par_for("en0:addrs", "bob")
                    .unwrap()
                    .split(",")
                    .next()
                    .unwrap()
                    .trim()
                    .parse::<Ipv6Addr>()
                    .unwrap(),
            )
            .await
            .unwrap();
        }));
    }

    async fn at_sim_end(&mut self) {
        for handle in self.handles.drain(..) {
            handle.await.unwrap();
        }
    }
}

#[derive(Default)]
struct AliceFailure {
    handles: Vec<JoinHandle<()>>,
}

impl AsyncModule for AliceFailure {
    async fn at_sim_start(&mut self, _stage: usize) {
        // add_interface(Interface::loopback()).unwrap();
        add_interface(Interface::ethv6_autocfg(NetworkDevice::eth())).unwrap();
        self.handles.push(tokio::spawn(async move {
            des::time::sleep(Duration::from_secs(10)).await;
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
        }));
    }

    async fn at_sim_end(&mut self) {
        for handle in self.handles.drain(..) {
            handle.await.unwrap();
        }
    }
}

#[derive(Default)]
struct Bob;

impl AsyncModule for Bob {
    async fn at_sim_start(&mut self, _stage: usize) {
        // add_interface(Interface::loopback()).unwrap();
        add_interface(Interface::ethv6_autocfg(NetworkDevice::eth())).unwrap();

        tokio::spawn(async {
            des::time::sleep(Duration::from_secs(5)).await;
            interface_status("en0").unwrap().write_to_par().unwrap();
        });
    }
}

#[derive(Default)]
struct Router;

impl AsyncModule for Router {
    async fn at_sim_start(&mut self, _stage: usize) {
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

type Switch = utils::LinkLayerSwitch;

#[test]
#[serial]
fn icmpv6_ping_success() -> Result<(), Box<dyn Error>> {
    type Alice = AliceSuccess;

    inet::init();
    // des::tracing::init();

    let app = Sim::ndl(
        "tests/icmpv6_ping.ndl",
        registry![Bob, Alice, Router, Switch, else _],
    )?;
    let rt = Builder::seeded(123).max_time(30.0.into()).build(app);
    let _res = rt.run();

    Ok(())
}

#[test]
#[serial]
fn icmpv6_ping_failure() -> Result<(), Box<dyn Error>> {
    // des::tracing::Subscriber::default().init().unwrap();
    type Alice = AliceFailure;

    inet::init();
    let app = Sim::ndl(
        "tests/icmpv6_ping.ndl",
        registry![Bob, Alice, Router, Switch, else _],
    )?;
    let rt = Builder::seeded(123).max_time(100.0.into()).build(app);
    let _res = rt.run();

    Ok(())
}
