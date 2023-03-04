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
        add_interface(Interface::ethernet(
            &[IpAddr::from_str("192.168.2.100").unwrap()],
            NetworkDevice::eth_default(),
        ));
    }
}
impl Module for B {
    fn new() -> Self {
        Self
    }

    fn at_sim_start(&mut self, _stage: usize) {
        add_interface(Interface::ethernet(
            &[IpAddr::from_str("192.168.2.200").unwrap()],
            NetworkDevice::eth_default(),
        ));
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

            assert_eq!(r.ports[0].output.pos(), 2);
            assert_eq!(r.ports[0].peer, None);

            assert_eq!(r.ports[1].output.pos(), 1);
            assert_eq!(
                r.ports[1].peer,
                Some(RoutingPeer {
                    addr: IpAddr::from_str("192.168.2.200").unwrap()
                })
            );

            assert_eq!(r.ports[2].output.pos(), 0);
            assert_eq!(
                r.ports[2].peer,
                Some(RoutingPeer {
                    addr: IpAddr::from_str("192.168.2.100").unwrap()
                })
            );
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
    //     .interal_max_log_level(log::LevelFilter::Info)
    //     .set_logger();

    let app = NetworkRuntime::new(
        NdlApplication::new("tests/triangle.ndl", registry![A, B, C, Main])
            .map_err(|e| println!("{e}"))
            .unwrap(),
    );
    let rt = Runtime::new_with(app, RuntimeOptions::seeded(123).max_time(100.0.into()));
    let _ = rt.run().unwrap();
}
