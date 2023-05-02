use std::iter::repeat_with;

use des::tokio::io::{AsyncReadExt, AsyncWriteExt};
use des::tokio::spawn;
use des::tokio::task::JoinHandle;
use des::tokio::time::sleep;
use des::{prelude::*, registry};
use inet::uds::{UnixListener, UnixStream};
use serial_test::serial;

struct Simplex {
    handles: Vec<JoinHandle<()>>,
}

#[async_trait::async_trait]
impl AsyncModule for Simplex {
    fn new() -> Self {
        Self {
            handles: Vec::new(),
        }
    }

    async fn at_sim_start(&mut self, _: usize) {
        self.handles.push(spawn(async move {
            let server = UnixListener::bind("/tmp/listener").unwrap();
            while let Ok((mut stream, from)) = server.accept().await {
                log::info!("stream established from {from:?}");
                sleep(Duration::from_secs(1)).await;

                let mut buf = [0; 512];
                loop {
                    let n = stream.read(&mut buf).await.unwrap();

                    if n == 0 {
                        log::info!("stream closed");
                        break;
                    }
                    log::info!("received {n} bytes");
                }
                break;
            }
        }));

        self.handles.push(spawn(async move {
            let mut client = UnixStream::connect("/tmp/listener").await.unwrap();
            log::info!("connected");
            sleep(Duration::from_secs(1)).await;

            client.write_all(&[42; 5000]).await.unwrap();
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
fn uds_simplex() {
    inet::init();
    // Logger::new()
    // .interal_max_log_level(log::LevelFilter::Trace)
    // .set_logger();

    type Main = Simplex;

    let app = NdlApplication::new("tests/main.ndl", registry![Main])
        .map_err(|e| println!("{e}"))
        .unwrap();
    let app = NetworkApplication::new(app);
    let rt = Runtime::new_with(app, RuntimeOptions::seeded(123).max_time(100.0.into()));
    match rt.run() {
        RuntimeResult::Finished { .. } => {}
        _ => panic!("Unexpected runtime result"),
    }
}

struct Duplex {
    handles: Vec<JoinHandle<()>>,
}

#[async_trait::async_trait]
impl AsyncModule for Duplex {
    fn new() -> Self {
        Self {
            handles: Vec::new(),
        }
    }

    async fn at_sim_start(&mut self, _: usize) {
        self.handles.push(spawn(async move {
            let server = UnixListener::bind("/tmp/listener").unwrap();
            while let Ok((mut stream, from)) = server.accept().await {
                log::info!("stream established from {from:?}");
                sleep(Duration::from_secs(1)).await;

                let mut buf = vec![0; 5000];
                stream.read_exact(&mut buf).await.unwrap();
                stream.write_all(&buf).await.unwrap();
                log::info!("stream closed");

                break;
            }
        }));

        self.handles.push(spawn(async move {
            let mut client = UnixStream::connect("/tmp/listener").await.unwrap();
            log::info!("connected");
            sleep(Duration::from_secs(1)).await;

            let wbuf = repeat_with(|| random()).take(5000).collect::<Vec<_>>();
            client.write_all(&wbuf).await.unwrap();

            let mut rbuf = Vec::with_capacity(5000);
            client.read_to_end(&mut rbuf).await.unwrap();

            assert_eq!(wbuf, rbuf);
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
fn uds_duplex() {
    inet::init();
    // Logger::new()
    // .interal_max_log_level(log::LevelFilter::Trace)
    // .set_logger();

    type Main = Duplex;

    let app = NdlApplication::new("tests/main.ndl", registry![Main])
        .map_err(|e| println!("{e}"))
        .unwrap();
    let app = NetworkApplication::new(app);
    let rt = Runtime::new_with(app, RuntimeOptions::seeded(123).max_time(100.0.into()));
    match rt.run() {
        RuntimeResult::Finished { .. } => {}
        _ => panic!("Unexpected runtime result"),
    }
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
        let (mut client, mut server) = UnixStream::pair().unwrap();

        self.handles.push(spawn(async move {
            sleep(Duration::from_secs(1)).await;

            let mut buf = vec![0; 5000];
            server.read_exact(&mut buf).await.unwrap();
            server.write_all(&buf).await.unwrap();
            log::info!("stream closed");
        }));

        self.handles.push(spawn(async move {
            sleep(Duration::from_secs(1)).await;

            let wbuf = repeat_with(|| random()).take(5000).collect::<Vec<_>>();
            client.write_all(&wbuf).await.unwrap();

            let mut rbuf = Vec::with_capacity(5000);
            client.read_to_end(&mut rbuf).await.unwrap();

            assert_eq!(wbuf, rbuf);
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
fn uds_stream_unnamed_pair() {
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
    match rt.run() {
        RuntimeResult::Finished { .. } => {}
        _ => panic!("Unexpected runtime result"),
    }
}
