use std::iter::repeat_with;

use des::{
    prelude::*,
    registry,
    tokio::{spawn, task::JoinHandle, time::sleep},
};
use inet::{
    arp::arpa,
    interface::{add_interface, Interface, NetworkDevice},
    UdpSocket,
};

// bitrate: 10_000_000
// latency: 50ms

const TOTAL_BYTES: usize = 10_000;

struct Ping {
    handle: Option<JoinHandle<()>>,
}
#[async_trait::async_trait]
impl AsyncModule for Ping {
    fn new() -> Ping {
        Ping { handle: None }
    }

    async fn at_sim_start(&mut self, _: usize) {
        add_interface(Interface::ethv4_named(
            "en0",
            NetworkDevice::eth(),
            [1, 1, 1, 1].into(),
            Ipv4Addr::UNSPECIFIED,
        ))
        .unwrap();

        self.handle = Some(spawn(async move {
            let mut c = 0;

            let sock = UdpSocket::bind("0.0.0.0:0").await.unwrap();
            sock.connect("2.2.2.2:1024").await.unwrap();

            let mut bytes = TOTAL_BYTES;
            while bytes > 0 {
                let d = Duration::from_micros(random::<u64>() % 100_000);
                log::info!("sleeping for {:?}", d);
                sleep(d).await;

                let n = ((random::<usize>() % 800) + 224).min(bytes);
                let buf = repeat_with(|| random::<u8>()).take(n).collect::<Vec<_>>();
                bytes -= n;

                let t0 = SimTime::now();

                sock.send(&buf).await.unwrap();
                let t1 = SimTime::now();

                if t0 != t1 {
                    c += 1;
                }
            }

            log::info!("{c} collisions");
            assert_eq!(c, 1);
        }));
    }

    async fn at_sim_end(&mut self) {
        let r = arpa().unwrap();
        for l in r {
            log::debug!("{l}")
        }

        self.handle.take().unwrap().await.unwrap();
    }
}

struct Pong {
    handle: Option<JoinHandle<()>>,
}
#[async_trait::async_trait]
impl AsyncModule for Pong {
    fn new() -> Pong {
        Pong { handle: None }
    }

    async fn at_sim_start(&mut self, _: usize) {
        add_interface(Interface::ethv4_named(
            "en0",
            NetworkDevice::eth(),
            [2, 2, 2, 2].into(),
            Ipv4Addr::UNSPECIFIED,
        ))
        .unwrap();

        self.handle = Some(spawn(async move {
            let mut bytes = 0;
            let sock = UdpSocket::bind("0.0.0.0:1024").await.unwrap();
            while bytes < TOTAL_BYTES {
                let mut buf = [0; 1024];
                let (n, _) = sock.recv_from(&mut buf).await.unwrap();
                bytes += n;
            }
        }));
    }

    async fn at_sim_end(&mut self) {
        let r = arpa().unwrap();
        for l in r {
            log::debug!("{l}")
        }

        self.handle.take().unwrap().await.unwrap();
    }
}

struct Main;
impl Module for Main {
    fn new() -> Main {
        Main
    }
}

#[test]
fn udp_busysend() {
    inet::init();
    // Logger::new().set_logger();

    let app = NdlApplication::new("tests/pingpong.ndl", registry![Ping, Pong, Main])
        .map_err(|e| println!("{e}"))
        .unwrap();
    let app = NetworkRuntime::new(app);
    let rt = Runtime::new_with(app, RuntimeOptions::seeded(123));
    let _ = rt.run();
}
