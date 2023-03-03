use des::{
    prelude::*,
    registry,
    tokio::{spawn, task::JoinHandle, time::sleep},
};
use inet::{
    interface::{add_interface, get_ip, Interface, NetworkDevice},
    utils::netstat,
    *,
};

const SCHED: [&'static [f64; 5]; 2] = [&SCHED_A, &SCHED_B];
const SCHED_A: [f64; 5] = [1., 3., 6., 7., 10.];
const SCHED_B: [f64; 5] = [2., 4., 5., 6.5, 11.];

const EXPECTED: [u8; 10] = [1, 2, 1, 2, 2, 1, 2, 1, 1, 2];

// A B A B B A B A A B

struct A {
    handle: Option<JoinHandle<()>>,
}
#[async_trait::async_trait]
impl AsyncModule for A {
    fn new() -> A {
        A { handle: None }
    }

    async fn at_sim_start(&mut self, _: usize) {
        let c = match &module_name()[..] {
            "a" => 1,
            "b" => 2,
            _ => unreachable!(),
        };
        add_interface(Interface::en0(
            random(),
            Ipv4Addr::new(c, c, c, c),
            NetworkDevice::eth_default(),
        ));

        self.handle = Some(spawn(async move {
            sleep(Duration::from_secs(1)).await;
            let sched = SCHED[(c - 1) as usize];
            let mut i = 0;

            let sock = UdpSocket::bind(("0.0.0.0", c as u16)).await.unwrap();
            sock.connect(("3.3.3.3", c as u16)).await.unwrap();

            while i < sched.len() {
                let rem = sched[i] - SimTime::now().as_secs_f64();
                sleep(Duration::from_secs_f64(rem)).await;
                i += 1;

                let text = format!("Hello from client {}", module_name());
                log::info!("sending from {}", get_ip().unwrap());
                sock.send(text.as_bytes()).await.unwrap();
            }
        }));
    }

    async fn at_sim_end(&mut self) {
        self.handle.take().unwrap().await.unwrap();
    }
}

type B = A;

struct C {
    handle: Option<JoinHandle<()>>,
}
#[async_trait::async_trait]
impl AsyncModule for C {
    fn new() -> C {
        C { handle: None }
    }

    async fn at_sim_start(&mut self, _: usize) {
        add_interface(Interface::en0(
            random(),
            Ipv4Addr::new(3, 3, 3, 3),
            NetworkDevice::eth_default(),
        ));

        self.handle = Some(spawn(async move {
            sleep(Duration::from_secs(1)).await;

            let mut i = 0;
            let sock_a = UdpSocket::bind(("0.0.0.0", 1)).await.unwrap();
            let sock_b = UdpSocket::bind(("0.0.0.0", 2)).await.unwrap();

            while i < EXPECTED.len() {
                let mut buf_a = [0u8; 1024];
                let mut buf_b = [0u8; 1024];
                des::tokio::select!(
                    r = sock_a.recv_from(&mut buf_a) => {
                        log::info!("received from a");
                        let _ = r.unwrap();
                        assert!(EXPECTED[i] == 1);
                        i += 1;

                    },
                    r = sock_b.recv_from(&mut buf_b) => {
                        log::info!("received from b");
                        let _ = r.unwrap();
                        assert!(EXPECTED[i] == 2);
                        i += 1;
                    },
                    else => log::error!("what happened"),
                );
            }

            println!("{:#?}", netstat());
        }));
    }

    async fn at_sim_end(&mut self) {
        self.handle.take().unwrap().await.unwrap();
    }
}

struct Main;
impl Module for Main {
    fn new() -> Self {
        Self
    }

    fn handle_message(&mut self, msg: Message) {
        let g = msg.header().last_gate.as_ref().unwrap().pos();
        match g {
            0 | 1 => send(msg, ("out", 2)),
            2 => panic!(),
            _ => unreachable!(),
        }
    }
}

#[test]
fn udp_select() {
    inet::init();
    // Logger::new()
    // .interal_max_log_level(log::LevelFilter::Info)
    // .set_logger();

    let app = NetworkRuntime::new(
        NdlApplication::new("tests/triangle.ndl", registry![A, B, C, Main])
            .map_err(|e| println!("{e}"))
            .unwrap(),
    );
    let rt = Runtime::new_with(app, RuntimeOptions::seeded(123).max_time(100.0.into()));
    let _ = rt.run().unwrap();
}
