#![cfg(feature = "uds")]

use std::iter::repeat_with;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use des::time::sleep;
use des::{prelude::*, registry};
use inet::uds::{UnixListener, UnixStream};
use serial_test::serial;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::spawn;

#[derive(Default)]
struct Simplex {
    done: Arc<AtomicUsize>,
}

impl Module for Simplex {
    fn at_sim_start(&mut self, _: usize) {
        let done = self.done.clone();
        spawn(async move {
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
            done.fetch_add(1, Ordering::SeqCst);
        });

        let done = self.done.clone();
        spawn(async move {
            let mut client = UnixStream::connect("/tmp/listener").await.unwrap();
            tracing::info!("connected");
            sleep(Duration::from_secs(1)).await;

            client.write_all(&[42; 5000]).await.unwrap();
            done.fetch_add(1, Ordering::SeqCst);
        });
    }

    fn at_sim_end(&mut self) {
        assert_eq!(self.done.load(Ordering::SeqCst), 2);
    }
}

#[test]
#[serial]
fn uds_simplex() {
    // Logger::new()
    // .interal_max_log_level(tracing::LevelFilter::Trace)
    // .set_logger();

    type Main = Simplex;

    let app = Sim::new(())
        .with_stack(inet::init)
        .with_ndl("tests/main.yml", registry![Main])
        .map_err(|e| println!("{e}"))
        .unwrap();
    let rt = Builder::seeded(123).max_time(100.0.into()).build(app);
    match rt.run() {
        RuntimeResult::Finished { .. } => {}
        _ => panic!("Unexpected runtime result"),
    }
}

#[derive(Default)]
struct Duplex {
    done: Arc<AtomicUsize>,
}

impl Module for Duplex {
    fn at_sim_start(&mut self, _: usize) {
        let done = self.done.clone();
        spawn(async move {
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
            done.fetch_add(1, Ordering::SeqCst);
        });

        let done = self.done.clone();
        spawn(async move {
            let mut client = UnixStream::connect("/tmp/listener").await.unwrap();
            tracing::info!("connected");
            sleep(Duration::from_secs(1)).await;

            let wbuf = repeat_with(|| random()).take(5000).collect::<Vec<_>>();
            client.write_all(&wbuf).await.unwrap();

            let mut rbuf = Vec::with_capacity(5000);
            client.read_to_end(&mut rbuf).await.unwrap();

            assert_eq!(wbuf, rbuf);
            done.fetch_add(1, Ordering::SeqCst);
        });
    }

    fn at_sim_end(&mut self) {
        assert_eq!(self.done.load(Ordering::SeqCst), 2);
    }
}

#[test]
#[serial]
fn uds_duplex() {
    // Logger::new()
    // .interal_max_log_level(tracing::LevelFilter::Trace)
    // .set_logger();

    type Main = Duplex;

    let app = Sim::new(())
        .with_stack(inet::init)
        .with_ndl("tests/main.yml", registry![Main])
        .map_err(|e| println!("{e}"))
        .unwrap();
    let rt = Builder::seeded(123).max_time(100.0.into()).build(app);
    match rt.run() {
        RuntimeResult::Finished { .. } => {}
        _ => panic!("Unexpected runtime result"),
    }
}

#[derive(Default)]
struct UnnamedPair {
    done: Arc<AtomicUsize>,
}

impl Module for UnnamedPair {
    fn at_sim_start(&mut self, _: usize) {
        let (mut client, mut server) = UnixStream::pair().unwrap();

        let done = self.done.clone();
        spawn(async move {
            sleep(Duration::from_secs(1)).await;

            let mut buf = vec![0; 5000];
            server.read_exact(&mut buf).await.unwrap();
            server.write_all(&buf).await.unwrap();
            tracing::info!("stream closed");
            done.fetch_add(1, Ordering::SeqCst);
        });

        let done = self.done.clone();
        spawn(async move {
            sleep(Duration::from_secs(1)).await;

            let wbuf = repeat_with(|| random()).take(5000).collect::<Vec<_>>();
            client.write_all(&wbuf).await.unwrap();

            let mut rbuf = Vec::with_capacity(5000);
            client.read_to_end(&mut rbuf).await.unwrap();

            assert_eq!(wbuf, rbuf);
            done.fetch_add(1, Ordering::SeqCst);
        });
    }

    fn at_sim_end(&mut self) {
        assert_eq!(self.done.load(Ordering::SeqCst), 2);
    }
}

#[test]
#[serial]
fn uds_stream_unnamed_pair() {
    // Logger::new()
    // .interal_max_log_level(tracing::LevelFilter::Trace)
    // .set_logger();

    type Main = UnnamedPair;

    let app = Sim::new(())
        .with_stack(inet::init)
        .with_ndl("tests/main.yml", registry![Main])
        .map_err(|e| println!("{e}"))
        .unwrap();
    let rt = Builder::seeded(123).max_time(100.0.into()).build(app);
    match rt.run() {
        RuntimeResult::Finished { .. } => {}
        _ => panic!("Unexpected runtime result"),
    }
}
