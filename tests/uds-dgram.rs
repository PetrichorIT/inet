use des::{
    prelude::*,
    registry,
    tokio::{spawn, task::JoinHandle, time::sleep},
};
use inet::uds::UnixDatagram;
use serial_test::serial;
use std::iter::repeat_with;

struct PathedDgrams {
    handles: Vec<JoinHandle<()>>,
}

#[async_trait::async_trait]
impl AsyncModule for PathedDgrams {
    fn new() -> Self {
        Self {
            handles: Vec::new(),
        }
    }

    async fn at_sim_start(&mut self, _: usize) {
        self.handles.push(spawn(async move {
            let sock = UnixDatagram::bind("/tmp/task1").unwrap();
            sleep(Duration::from_secs(1)).await;

            // Echo
            for _ in 0..10 {
                let mut buf = [0; 512];
                let (n, from) = sock.recv_from(&mut buf).await.unwrap();

                sock.send_to(&buf[..n], from.as_pathname().unwrap())
                    .await
                    .unwrap();
            }
        }));

        self.handles.push(spawn(async move {
            let sock = UnixDatagram::bind("/tmp/task2").unwrap();
            for i in 0..3 {
                let n = 200 + random::<usize>() % 200;
                let buf = repeat_with(|| random::<u8>()).take(n).collect::<Vec<_>>();

                sock.send_to(&buf, "/tmp/task1").await.unwrap();
                let mut rbuf = [0; 512];
                let (nn, from) = sock.recv_from(&mut rbuf).await.unwrap();

                assert_eq!(n, nn);
                assert_eq!(buf[..n], rbuf[..n]);

                sleep(Duration::from_secs_f64(random())).await;
            }
        }));

        self.handles.push(spawn(async move {
            let sock = UnixDatagram::bind("/tmp/task3").unwrap();
            for i in 0..7 {
                let n = 200 + random::<usize>() % 200;
                let buf = repeat_with(|| random::<u8>()).take(n).collect::<Vec<_>>();

                sock.send_to(&buf, "/tmp/task1").await.unwrap();
                let mut rbuf = [0; 512];
                let (nn, from) = sock.recv_from(&mut rbuf).await.unwrap();

                assert_eq!(n, nn);
                assert_eq!(buf[..n], rbuf[..n]);

                sleep(Duration::from_secs_f64(random())).await;
            }
        }));
    }

    async fn at_sim_end(&mut self) {
        for handle in self.handles.drain(..) {
            handle.await.unwrap();
        }
    }
}

#[test]
#[serial]
fn uds_pathed_dgrams() {
    inet::init();
    // Logger::new()
    // .interal_max_log_level(log::LevelFilter::Trace)
    // .set_logger();

    type Main = PathedDgrams;

    let app = NdlApplication::new("tests/main.ndl", registry![Main])
        .map_err(|e| println!("{e}"))
        .unwrap();
    let app = NetworkApplication::new(app);
    let rt = Runtime::new_with(app, RuntimeOptions::seeded(123).max_time(100.0.into()));
    let _ = rt.run().unwrap();
}

struct UnnamedPair {
    handles: Vec<JoinHandle<()>>,
}

#[async_trait::async_trait]
impl AsyncModule for UnnamedPair {
    fn new() -> Self {
        Self {
            handles: Vec::new(),
        }
    }

    async fn at_sim_start(&mut self, _: usize) {
        let (a, b) = UnixDatagram::pair().unwrap();

        self.handles.push(spawn(async move {
            for i in 0..10 {
                a.send(&[1, 2, 3]).await.unwrap();
                sleep(Duration::from_secs_f64(random())).await;
            }

            for i in 0..10 {
                a.recv(&mut [0; 500]).await.unwrap();
            }
        }));

        self.handles.push(spawn(async move {
            for i in 0..10 {
                b.send(&[1, 2, 3]).await.unwrap();
                sleep(Duration::from_secs_f64(random())).await;
            }

            for i in 0..10 {
                b.recv(&mut [0; 500]).await.unwrap();
            }
        }));
    }

    async fn at_sim_end(&mut self) {
        for handle in self.handles.drain(..) {
            handle.await.unwrap();
        }
    }
}

#[test]
#[serial]
fn uds_pair() {
    inet::init();
    // Logger::new()
    // .interal_max_log_level(log::LevelFilter::Trace)
    // .set_logger();

    type Main = UnnamedPair;

    let app = NdlApplication::new("tests/main.ndl", registry![Main])
        .map_err(|e| println!("{e}"))
        .unwrap();
    let app = NetworkApplication::new(app);
    let rt = Runtime::new_with(app, RuntimeOptions::seeded(123).max_time(100.0.into()));
    let _ = rt.run().unwrap();
}

struct FailAtDoubleBinding {
    handles: Vec<JoinHandle<()>>,
}

#[async_trait::async_trait]
impl AsyncModule for FailAtDoubleBinding {
    fn new() -> Self {
        Self {
            handles: Vec::new(),
        }
    }

    async fn at_sim_start(&mut self, _: usize) {
        let a = UnixDatagram::bind("/a/b/c").unwrap();
        let b = UnixDatagram::bind("/a/b/c");
        assert!(b.is_err());
    }

    async fn at_sim_end(&mut self) {
        for handle in self.handles.drain(..) {
            handle.await.unwrap();
        }
    }
}

#[test]
#[serial]
fn double_bind() {
    inet::init();
    // Logger::new()
    // .interal_max_log_level(log::LevelFilter::Trace)
    // .set_logger();

    type Main = UnnamedPair;

    let app = NdlApplication::new("tests/main.ndl", registry![Main])
        .map_err(|e| println!("{e}"))
        .unwrap();
    let app = NetworkApplication::new(app);
    let rt = Runtime::new_with(app, RuntimeOptions::seeded(123).max_time(100.0.into()));
    let _ = rt.run().unwrap();
}
