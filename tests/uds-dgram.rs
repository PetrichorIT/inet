use des::{
    prelude::*,
    registry,
    tokio::{spawn, task::JoinHandle, time::sleep},
};
use inet::{fs, uds::UnixDatagram};
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
            for _i in 0..3 {
                let n = 200 + random::<usize>() % 200;
                let buf = repeat_with(|| random::<u8>()).take(n).collect::<Vec<_>>();

                sock.send_to(&buf, "/tmp/task1").await.unwrap();
                let mut rbuf = [0; 512];
                let (nn, _from) = sock.recv_from(&mut rbuf).await.unwrap();

                assert_eq!(n, nn);
                assert_eq!(buf[..n], rbuf[..n]);

                sleep(Duration::from_secs_f64(random())).await;
            }
        }));

        self.handles.push(spawn(async move {
            let sock = UnixDatagram::bind("/tmp/task3").unwrap();
            for _i in 0..7 {
                let n = 200 + random::<usize>() % 200;
                let buf = repeat_with(|| random::<u8>()).take(n).collect::<Vec<_>>();

                sock.send_to(&buf, "/tmp/task1").await.unwrap();
                let mut rbuf = [0; 512];
                let (nn, _from) = sock.recv_from(&mut rbuf).await.unwrap();

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
            for _i in 0..10 {
                a.send(&[1, 2, 3]).await.unwrap();
                sleep(Duration::from_secs_f64(random())).await;
            }

            for _i in 0..10 {
                a.recv(&mut [0; 500]).await.unwrap();
            }
        }));

        self.handles.push(spawn(async move {
            for _i in 0..10 {
                b.send(&[1, 2, 3]).await.unwrap();
                sleep(Duration::from_secs_f64(random())).await;
            }

            for _i in 0..10 {
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
        let _a = UnixDatagram::bind("/a/b/c").unwrap();
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

    type Main = FailAtDoubleBinding;

    let app = NdlApplication::new("tests/main.ndl", registry![Main])
        .map_err(|e| println!("{e}"))
        .unwrap();
    let app = NetworkApplication::new(app);
    let rt = Runtime::new_with(app, RuntimeOptions::seeded(123).max_time(100.0.into()));
    match rt.run() {
        RuntimeResult::EmptySimulation { .. } => {}
        _ => panic!("Unexpected runtime result"),
    }
}

struct NamedTempdir {
    handles: Vec<JoinHandle<()>>,
}

#[async_trait::async_trait]
impl AsyncModule for NamedTempdir {
    fn new() -> Self {
        Self {
            handles: Vec::new(),
        }
    }

    async fn at_sim_start(&mut self, _: usize) {
        let tmp = fs::tempdir().unwrap();

        // Bind each socket to a filesystem path
        let tx_path = tmp.path().join("tx");
        let tx = UnixDatagram::bind(&tx_path).unwrap();
        let rx_path = tmp.path().join("rx");
        let rx = UnixDatagram::bind(&rx_path).unwrap();

        log::info!("tx: {tx_path:?} rx: {rx_path:?}");

        let bytes = b"hello world";
        tx.send_to(bytes, &rx_path).await.unwrap();

        let mut buf = vec![0u8; 24];
        let (size, addr) = rx.recv_from(&mut buf).await.unwrap();

        let dgram = &buf[..size];
        assert_eq!(dgram, bytes);
        assert_eq!(addr.as_pathname().unwrap(), &tx_path);
    }

    async fn at_sim_end(&mut self) {
        for handle in self.handles.drain(..) {
            handle.await.unwrap();
        }
    }
}

#[test]
#[serial]
fn uds_named_tempdir() {
    inet::init();
    // Logger::new()
    // .interal_max_log_level(log::LevelFilter::Trace)
    // .set_logger();

    type Main = NamedTempdir;

    let app = NdlApplication::new("tests/main.ndl", registry![Main])
        .map_err(|e| println!("{e}"))
        .unwrap();
    let app = NetworkApplication::new(app);
    let rt = Runtime::new_with(app, RuntimeOptions::seeded(123).max_time(100.0.into()));
    match rt.run() {
        RuntimeResult::EmptySimulation { .. } => {}
        _ => panic!("Unexpected runtime result"),
    }
}
