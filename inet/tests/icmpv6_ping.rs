use std::{error::Error, io::ErrorKind, net::Ipv6Addr, time::Duration};

use des::{ndl::NdlApplication, net::module::AsyncModule, registry, runtime::Builder};
use inet::{
    interface::{add_interface, Interface, NetworkDevice},
    ipv6::{self, util::setup_router},
    routing::RoutingPort,
    utils,
};
use serial_test::serial;
use tokio::task::JoinHandle;

#[macro_use]
mod common;

struct AliceSuccess {
    handles: Vec<JoinHandle<()>>,
}
impl_build_named!(AliceSuccess);
impl AsyncModule for AliceSuccess {
    fn new() -> Self {
        AliceSuccess {
            handles: Vec::new(),
        }
    }

    async fn at_sim_start(&mut self, _stage: usize) {
        add_interface(Interface::loopback()).unwrap();
        add_interface(Interface::ethv6_autocfg(NetworkDevice::eth())).unwrap();
        self.handles.push(tokio::spawn(async move {
            des::time::sleep(Duration::from_secs(1)).await;
            let _ping = ipv6::icmp::ping::ping(
                "2003:c1:e719:8fff:fc85:8aff:fed5:1c9d"
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

struct AliceFailure {
    handles: Vec<JoinHandle<()>>,
}
impl_build_named!(AliceFailure);
impl AsyncModule for AliceFailure {
    fn new() -> Self {
        AliceFailure {
            handles: Vec::new(),
        }
    }

    async fn at_sim_start(&mut self, _stage: usize) {
        add_interface(Interface::loopback()).unwrap();
        add_interface(Interface::ethv6_autocfg(NetworkDevice::eth())).unwrap();
        self.handles.push(tokio::spawn(async move {
            des::time::sleep(Duration::from_secs(1)).await;
            let err = ipv6::icmp::ping::ping(
                "2003:c1:e719:8fff:2222:1111:0000:3333"
                    .parse::<Ipv6Addr>()
                    .unwrap(),
            )
            .await
            .unwrap_err();

            assert_eq!(err.kind(), ErrorKind::ConnectionRefused);
        }));
    }

    async fn at_sim_end(&mut self) {
        for handle in self.handles.drain(..) {
            handle.await.unwrap();
        }
    }
}

struct Bob;
impl_build_named!(Bob);
impl AsyncModule for Bob {
    fn new() -> Self {
        Bob
    }

    async fn at_sim_start(&mut self, _stage: usize) {
        add_interface(Interface::loopback()).unwrap();
        add_interface(Interface::ethv6_autocfg(NetworkDevice::eth())).unwrap();
    }
}

struct Router;
impl_build_named!(Router);
impl AsyncModule for Router {
    fn new() -> Self {
        Router
    }

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

struct Main;
impl_build_named!(Main);
impl AsyncModule for Main {
    fn new() -> Self {
        Main
    }
}

type Switch = utils::LinkLayerSwitch;

#[test]
#[serial]
fn icmpv6_ping_success() -> Result<(), Box<dyn Error>> {
    type Alice = AliceSuccess;

    inet::init();
    let app = NdlApplication::new(
        "tests/icmpv6_ping.ndl",
        registry![Bob, Alice, Router, Switch, Main],
    )?;
    let rt = Builder::seeded(123)
        .max_time(10.0.into())
        .build(app.into_app());
    let _res = rt.run();

    Ok(())
}

#[test]
#[serial]
fn icmpv6_ping_failure() -> Result<(), Box<dyn Error>> {
    des::tracing::Subscriber::default().init().unwrap();
    type Alice = AliceFailure;

    inet::init();
    let app = NdlApplication::new(
        "tests/icmpv6_ping.ndl",
        registry![Bob, Alice, Router, Switch, Main],
    )?;
    let rt = Builder::seeded(123)
        .max_time(10.0.into())
        .build(app.into_app());
    let _res = rt.run();

    Ok(())
}
