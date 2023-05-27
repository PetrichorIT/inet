use std::str::FromStr;

use des::{prelude::*, registry};
use inet::{
    interface::{add_interface, Interface, NetworkDevice},
    routing::{RoutingInformation, RoutingPeer},
};

struct A;
struct B;
struct C;
struct Main;

impl Module for A {
    fn new() -> Self {
        Self
    }

    fn at_sim_start(&mut self, _stage: usize) {
        add_interface(Interface::ethv4(
            NetworkDevice::eth(),
            Ipv4Addr::from_str("192.168.2.100").unwrap(),
        ))
        .unwrap();
    }
}
impl Module for B {
    fn new() -> Self {
        Self
    }

    fn at_sim_start(&mut self, _stage: usize) {
        add_interface(Interface::ethv4(
            NetworkDevice::eth(),
            Ipv4Addr::from_str("192.168.2.200").unwrap(),
        ))
        .unwrap();
    }
}
impl Module for C {
    fn new() -> Self {
        Self
    }
}

impl Module for Main {
    fn new() -> Self {
        Self
    }
    fn at_sim_start(&mut self, stage: usize) {
        if stage == 1 {
            let r = RoutingInformation::collect();

            println!("{r:#?}");

            assert_eq!(r.ports[0].output.pos(), 0);
            assert_eq!(
                r.ports[0].peer,
                Some(RoutingPeer {
                    addr: IpAddr::from_str("192.168.2.100").unwrap()
                })
            );

            assert_eq!(r.ports[1].output.pos(), 1);
            assert_eq!(
                r.ports[1].peer,
                Some(RoutingPeer {
                    addr: IpAddr::from_str("192.168.2.200").unwrap()
                })
            );

            assert_eq!(r.ports[2].output.pos(), 2);
            assert_eq!(r.ports[2].peer, None);
        }
    }
    fn num_sim_start_stages(&self) -> usize {
        2
    }
}

#[test]
fn routing_info() {
    inet::init();
    // Logger::new()
    //     .interal_max_log_level(tracing::LevelFilter::Info)
    //     .set_logger();

    let app = NetworkApplication::new(
        NdlApplication::new("tests/triangle.ndl", registry![A, B, C, Main])
            .map_err(|e| println!("{e}"))
            .unwrap(),
    );
    let rt = Runtime::new_with(app, RuntimeOptions::seeded(123).max_time(100.0.into()));
    match rt.run() {
        RuntimeResult::EmptySimulation { .. } => {}
        _ => panic!("unexpected runtime result"),
    }
}
