use des::registry;
use std::{
    str::FromStr,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU32, Ordering::SeqCst},
    },
};

use des::prelude::*;
use inet::{
    interface::*,
    ioctx,
    socket::{AsRawFd, Fd},
    tcp::{Config, TcpListener, TcpStream, set_config},
};
use serial_test::serial;

#[derive(Default)]
struct Link {}
impl Module for Link {
    fn handle_message(&mut self, msg: Message) {
        let _ = match msg.header.last_gate.as_ref().map(|v| v.name()) {
            Some("lhs") => send(msg, "rhs"),
            Some("rhs") => send(msg, "lhs"),
            _ => todo!(),
        };
    }
}

#[derive(Default)]
struct TcpServer {
    done: Arc<AtomicBool>,
    fd: Arc<AtomicU32>,
}

impl Module for TcpServer {
    fn at_sim_start(&mut self, _: usize) {
        ioctx()
            .add_interface(
                InterfaceDef::new("en0", NetworkDevice::eth())
                    .ip(Ipv4Addr::new(69, 0, 0, 100).into()),
            )
            .unwrap();

        let done = self.done.clone();
        let fd = self.fd.clone();

        tokio::spawn(async move {
            let mut cfg = Config::default();
            cfg.mss = Some(536);
            set_config(cfg);

            let sock = TcpListener::bind("0.0.0.0:2000").await.unwrap();
            tracing::info!("Server bound");
            assert_eq!(
                sock.local_addr().unwrap(),
                SocketAddr::from_str("0.0.0.0:2000").unwrap()
            );

            let (mut stream, addr) = sock.accept().await.unwrap();
            tracing::info!("Established stream");
            fd.store(stream.as_raw_fd(), SeqCst);
            assert_eq!(addr, SocketAddr::from_str("69.0.0.200:1024").unwrap());

            use tokio::io::AsyncReadExt;
            let mut buf = [0u8; 500];
            let mut acc = 0;
            loop {
                let Ok(n) = stream.read(&mut buf).await else {
                    break;
                };
                tracing::info!("received {} bytes", n);

                if n == 0 {
                    panic!("Unexpected closing event - should be prevented by simultaneous close")
                } else {
                    acc += n;
                    if acc == 2000 {
                        break;
                    }
                };
            }

            let t = SimTime::now();
            let d = SimTime::from_duration(Duration::from_secs(1)) - t;
            tracing::info!("Waiting for {d:?}");
            des::time::sleep(d).await;

            tracing::info!("Server done");
            done.store(true, SeqCst);
            drop(stream);
            drop(sock);
        });
    }

    fn handle_message(&mut self, _: Message) {
        tracing::error!("All packet should have been caught by the plugins");
    }

    fn at_sim_end(&mut self) -> Result<(), RuntimeError> {
        assert!(self.done.load(SeqCst));

        let fd: Fd = self.fd.load(SeqCst);
        assert!(fd != 0);
        assert!(inet::socket::bsd_socket_info(fd).is_err());
        Ok(())
    }
}

#[derive(Default)]
struct TcpClient {
    done: Arc<AtomicBool>,
    fd: Arc<AtomicU32>,
}

impl Module for TcpClient {
    fn at_sim_start(&mut self, _: usize) {
        ioctx()
            .add_interface(
                InterfaceDef::new("en0", NetworkDevice::eth())
                    .ip(Ipv4Addr::new(69, 0, 0, 200).into()),
            )
            .unwrap();

        let done = self.done.clone();
        let fd = self.fd.clone();

        tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            let mut stream = TcpStream::connect("69.0.0.100:2000").await.unwrap();

            tracing::info!("Established stream");
            fd.store(stream.as_raw_fd(), SeqCst);

            let buf = vec![42; 2000];
            stream.write_all(&buf).await.unwrap();

            let t = SimTime::now();
            let d = SimTime::from_duration(Duration::from_secs(1)) - t;
            tracing::info!("Waiting for {d:?}");
            des::time::sleep(d).await;

            tracing::info!("Client done");
            done.store(true, SeqCst);
            drop(stream);
        });
    }

    fn handle_message(&mut self, _: Message) {
        panic!("All packet should have been caught by the plugins")
    }

    fn at_sim_end(&mut self) -> Result<(), RuntimeError> {
        assert!(self.done.load(SeqCst));

        let fd: Fd = self.fd.load(SeqCst);
        assert!(fd != 0);
        assert!(inet::socket::bsd_socket_info(fd).is_err());
        Ok(())
    }
}

#[test]
#[serial]
fn tcp_simulaneous_close() {
    let app = Sim::new(())
        .with_stack(inet::init)
        .with_ndl(
            "tests/tcp.yml",
            registry![Link, TcpServer, TcpClient, else _],
        )
        .map_err(|e| println!("{e}"))
        .unwrap();
    let rt = Builder::seeded(123)
        .max_time(10.0.into())
        .build(app.freeze());
    let (_, _, profiler) = rt.run().unwrap();
    assert!(profiler.event_count < 200);
}
