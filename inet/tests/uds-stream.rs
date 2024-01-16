#![cfg(feature = "uds")]

use std::iter::repeat_with;

use des::time::sleep;
use des::{prelude::*, registry};
use inet::uds::{UnixListener, UnixStream};
use serial_test::serial;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::spawn;
use tokio::task::JoinHandle;

struct Simplex {
    handles: Vec<JoinHandle<()>>,
}

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
                tracing::info!("stream established from {from:?}");
                sleep(Duration::from_secs(1)).await;

                let mut buf = [0; 512];
                loop {
                    let n = stream.read(&mut buf).await.unwrap();

                    if n == 0 {
                        tracing::info!("stream closed");
                        break;
                    }
                    tracing::info!("received {n} bytes");
                }
                break;
            }
        }));

        self.handles.push(spawn(async move {
            let mut client = UnixStream::connect("/tmp/listener").await.unwrap();
            tracing::info!("connected");
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
    // .interal_max_log_level(tracing::LevelFilter::Trace)
    // .set_logger();

    type Main = Simplex;

    let app = NdlApplication::new("tests/main.ndl", registry![Main])
        .map_err(|e| println!("{e}"))
        .unwrap();
    let app = NetworkApplication::new(app);
    let rt = Builder::seeded(123).max_time(100.0.into()).build(app);
    match rt.run() {
        RuntimeResult::Finished { .. } => {}
        _ => panic!("Unexpected runtime result"),
    }
}

struct Duplex {
    handles: Vec<JoinHandle<()>>,
}

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
                tracing::info!("stream established from {from:?}");
                sleep(Duration::from_secs(1)).await;

                let mut buf = vec![0; 5000];
                stream.read_exact(&mut buf).await.unwrap();
                stream.write_all(&buf).await.unwrap();
                tracing::info!("stream closed");

                break;
            }
        }));

        self.handles.push(spawn(async move {
            let mut client = UnixStream::connect("/tmp/listener").await.unwrap();
            tracing::info!("connected");
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
    // .interal_max_log_level(tracing::LevelFilter::Trace)
    // .set_logger();

    type Main = Duplex;

    let app = NdlApplication::new("tests/main.ndl", registry![Main])
        .map_err(|e| println!("{e}"))
        .unwrap();
    let app = NetworkApplication::new(app);
    let rt = Builder::seeded(123).max_time(100.0.into()).build(app);
    match rt.run() {
        RuntimeResult::Finished { .. } => {}
        _ => panic!("Unexpected runtime result"),
    }
}

struct UnnamedPair {
    handles: Vec<JoinHandle<()>>,
}

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
            tracing::info!("stream closed");
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
    // .interal_max_log_level(tracing::LevelFilter::Trace)
    // .set_logger();

    type Main = UnnamedPair;

    let app = NdlApplication::new("tests/main.ndl", registry![Main])
        .map_err(|e| println!("{e}"))
        .unwrap();
    let app = NetworkApplication::new(app);
    let rt = Builder::seeded(123).max_time(100.0.into()).build(app);
    match rt.run() {
        RuntimeResult::Finished { .. } => {}
        _ => panic!("Unexpected runtime result"),
    }
}
