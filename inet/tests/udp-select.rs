use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

use des::{prelude::*, registry, time::sleep};
use inet::{
    interface::{add_interface, Interface, NetworkDevice},
    utils::{get_ip, netstat},
    *,
};
use tokio::spawn;

const SCHED: [&'static [f64; 5]; 2] = [&SCHED_A, &SCHED_B];
const SCHED_A: [f64; 5] = [1., 3., 6., 7., 10.];
const SCHED_B: [f64; 5] = [2., 4., 5., 6.5, 11.];

const EXPECTED: [u8; 10] = [1, 2, 1, 2, 2, 1, 2, 1, 1, 2];

// A B A B B A B A A B

#[derive(Default)]
struct A {
    done: Arc<AtomicBool>,
}
impl Module for A {
    fn at_sim_start(&mut self, _: usize) {
        let c = match &current().name()[..] {
            "a" => 1,
            "b" => 2,
            _ => unreachable!(),
        };
        add_interface(Interface::ethv4_named(
            "en0",
            NetworkDevice::eth(),
            Ipv4Addr::new(192, 168, 0, c),
            Ipv4Addr::new(255, 255, 255, 0),
        ))
        .unwrap();

        let done = self.done.clone();
        spawn(async move {
            sleep(Duration::from_secs(1)).await;
            let sched = SCHED[(c - 1) as usize];
            let mut i = 0;

            let sock = UdpSocket::bind(("0.0.0.0", c as u16)).await.unwrap();
            sock.connect(("192.168.0.3", c as u16)).await.unwrap();

            while i < sched.len() {
                let rem = sched[i] - SimTime::now().as_secs_f64();
                sleep(Duration::from_secs_f64(rem)).await;
                i += 1;

                let text = format!("Hello from client {}", current().name());
                tracing::info!("sending from {}", get_ip().unwrap());
                sock.send(text.as_bytes()).await.unwrap();
            }
            done.store(true, Ordering::SeqCst);
        });
    }

    fn at_sim_end(&mut self) {
        assert!(self.done.load(Ordering::SeqCst));
    }
}

type B = A;

#[derive(Default)]
struct C {
    done: Arc<AtomicBool>,
}

impl Module for C {
    fn at_sim_start(&mut self, _: usize) {
        add_interface(Interface::ethv4_named(
            "en0",
            NetworkDevice::eth(),
            Ipv4Addr::new(192, 168, 0, 3),
            Ipv4Addr::new(255, 255, 255, 0),
        ))
        .unwrap();

        let done = self.done.clone();
        spawn(async move {
            sleep(Duration::from_secs(1)).await;

            let mut i = 0;
            let sock_a = UdpSocket::bind(("0.0.0.0", 1)).await.unwrap();
            let sock_b = UdpSocket::bind(("0.0.0.0", 2)).await.unwrap();

            while i < EXPECTED.len() {
                let mut buf_a = [0u8; 1024];
                let mut buf_b = [0u8; 1024];
                tokio::select!(
                    r = sock_a.recv_from(&mut buf_a) => {
                        tracing::info!("received from a");
                        let _ = r.unwrap();
                        assert!(EXPECTED[i] == 1);
                        i += 1;

                    },
                    r = sock_b.recv_from(&mut buf_b) => {
                        tracing::info!("received from b");
                        let _ = r.unwrap();
                        assert!(EXPECTED[i] == 2);
                        i += 1;
                    },
                    else => tracing::error!("what happened"),
                );
            }

            println!("{:#?}", netstat());
            done.store(true, Ordering::SeqCst);
        });
    }

    fn at_sim_end(&mut self) {
        assert!(self.done.load(Ordering::SeqCst));
    }
}

type Main = inet::utils::LinkLayerSwitch;

#[test]
fn udp_select() {
    // Logger::new()
    // .interal_max_log_level(tracing::LevelFilter::Info)
    // .set_logger();

    let app = Sim::new(())
        .with_stack(inet::init)
        .with_ndl("tests/triangle.yml", registry![A, B, C, Main])
        .map_err(|e| println!("{e}"))
        .unwrap();
    let rt = Builder::seeded(123).max_time(100.0.into()).build(app);
    let _ = rt.run().unwrap();
}
