use std::sync::Arc;

use des::{
    prelude::*,
    registry,
    tokio::{spawn, sync::Mutex, task::JoinHandle, time::sleep},
};
use inet::{
    interface::{add_interface, Interface, NetworkDevice},
    *,
};

struct Ping {
    out: Arc<Vec<u8>>,
    echoed: Arc<Mutex<Vec<u8>>>,
    handle: Option<JoinHandle<()>>,
}
#[async_trait::async_trait]
impl AsyncModule for Ping {
    fn new() -> Self {
        Self {
            out: Arc::new(std::iter::repeat_with(|| random()).take(4098).collect()),
            echoed: Arc::new(Mutex::new(Vec::with_capacity(4098))),
            handle: None,
        }
    }

    async fn at_sim_start(&mut self, _: usize) {
        add_interface(Interface::ethv4(
            NetworkDevice::eth(),
            Ipv4Addr::new(1, 1, 1, 1),
        ))
        .unwrap();

        let out = self.out.clone();
        let echoed = self.echoed.clone();
        self.handle = Some(spawn(async move {
            sleep(Duration::from_secs(1)).await;

            let socket = UdpSocket::bind("0.0.0.0:100").await.unwrap();
            socket.connect("2.2.2.2:200").await.unwrap();

            let mut cursor = 0;
            let mut c = 0;
            while cursor < out.len() {
                let remaning = out.len() - cursor;
                let size = random::<usize>() % (1024.min(remaning));
                let size = size.max(256).min(remaning);

                socket.send(&out[cursor..(cursor + size)]).await.unwrap();
                cursor += size;

                let d = Duration::from_secs_f64(random::<f64>());
                // log::info!("sleep({d:?})");
                sleep(d).await;
                c += 1;
            }

            log::info!("send all {c} packets");

            loop {
                // still work to do ?

                let lock = echoed.lock().await;
                if lock.len() >= out.len() {
                    break;
                }
                drop(lock);

                // Receive contents
                let mut buf = [0u8; 1024];
                let n = socket.recv(&mut buf).await.unwrap();

                let mut lock = echoed.lock().await;
                lock.extend(&buf[..n]);
            }
        }));
    }

    async fn handle_message(&mut self, _m: Message) {
        panic!()
    }

    async fn at_sim_end(&mut self) {
        let handle = self.handle.take().unwrap();
        assert!(handle.is_finished());
        handle.await.unwrap();

        assert_eq!(*self.out, *self.echoed.try_lock().unwrap());
    }
}

struct Pong {
    handle: Option<JoinHandle<()>>,
}
#[async_trait::async_trait]
impl AsyncModule for Pong {
    fn new() -> Self {
        Self { handle: None }
    }

    async fn at_sim_start(&mut self, _: usize) {
        add_interface(Interface::ethv4(
            NetworkDevice::eth(),
            Ipv4Addr::new(2, 2, 2, 2),
        ))
        .unwrap();

        self.handle = Some(spawn(async move {
            sleep(Duration::from_secs(1)).await;

            let socket = UdpSocket::bind("0.0.0.0:200").await.unwrap();
            let mut acc = 0;
            while acc < 4098 {
                let mut buf = [0u8; 1024];
                let (n, from) = socket.recv_from(&mut buf).await.unwrap();
                dbg!(from);
                acc += n;
                socket.send_to(&buf[..n], from).await.unwrap();
            }
        }));
    }
}

struct Main;
impl Module for Main {
    fn new() -> Self {
        Self
    }
}

#[test]
fn udp_pingpong() {
    inet::init();
    // Logger::new()
    // .interal_max_log_level(log::LevelFilter::Trace)
    // .set_logger();

    let app = NetworkRuntime::new(
        NdlApplication::new("tests/pingpong.ndl", registry![Ping, Pong, Main])
            .map_err(|e| println!("{e}"))
            .unwrap(),
    );
    let rt = Runtime::new_with(app, RuntimeOptions::seeded(123).max_time(100.0.into()));
    let _ = rt.run().unwrap();
}
