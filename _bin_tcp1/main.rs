use std::{io::ErrorKind, str::FromStr};

use des::prelude::*;
use inet::{interface::*, tcp::TcpDebugPlugin, TcpSocket};

#[NdlModule("bin")]
struct ManInTheMiddle {}
impl Module for ManInTheMiddle {
    fn new() -> Self {
        Self {}
    }

    fn handle_message(&mut self, msg: Message) {
        match msg.header().last_gate.as_ref().map(|v| v.name()) {
            Some("lhs_in") => send(msg, "rhs_out"),
            Some("rhs_in") => send(msg, "lhs_out"),
            _ => todo!(),
        }
    }
}

#[NdlModule("bin")]
struct Server {}
#[async_trait::async_trait]
impl AsyncModule for Server {
    fn new() -> Self {
        Self {}
    }
    async fn at_sim_start(&mut self, _: usize) {
        add_plugin(TcpDebugPlugin, 1);

        add_interface(Interface::en0(
            random(),
            Ipv4Addr::new(100, 100, 100, 100),
            NetworkDevice::eth_default(),
        ));

        tokio::spawn(async move {
            let sock = TcpSocket::new_v4().unwrap();
            sock.bind(SocketAddr::from_str("0.0.0.0:2000").unwrap())
                .unwrap();

            sock.set_send_buffer_size(1024).unwrap();
            sock.set_recv_buffer_size(1024).unwrap();

            let sock = sock.listen(1024).unwrap();

            // let sock = TcpListener::bind("0.0.0.0:2000").await.unwrap();
            log::info!("Server bound");

            let (mut stream, _) = sock.accept().await.unwrap();
            log::info!("Established stream");

            let mut buf = [0u8; 100];
            let err = stream.try_read(&mut buf).unwrap_err();
            assert_eq!(err.kind(), ErrorKind::WouldBlock);

            use tokio::io::AsyncReadExt;
            let mut buf = [0u8; 500];
            let mut acc = 0;
            loop {
                let Ok(n) = stream.read(&mut buf).await else { break };
                log::info!("received {} bytes", n);

                if n == 0 {
                    // Socket closed
                    break;
                } else {
                    acc += n;
                    if acc == 2000 {
                        break;
                    }
                };
            }

            let t = SimTime::now();
            let d = SimTime::from_duration(Duration::from_secs(1)) - t;
            log::info!("Waiting for {d:?}");
            tokio::time::sleep(d).await;

            log::info!("Server done");
            drop(stream);
            drop(sock);
        });
    }
    async fn handle_message(&mut self, _: Message) {
        log::error!("HM?");
    }
}

#[NdlModule("bin")]
struct Client {}
#[async_trait::async_trait]
impl AsyncModule for Client {
    fn new() -> Self {
        Self {}
    }
    async fn at_sim_start(&mut self, _: usize) {
        add_plugin(TcpDebugPlugin, 1);

        add_interface(Interface::en0(
            random(),
            Ipv4Addr::new(200, 200, 200, 200),
            NetworkDevice::eth_default(),
        ));

        tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            let sock = TcpSocket::new_v4().unwrap();
            sock.set_send_buffer_size(1024).unwrap();
            sock.set_recv_buffer_size(1024).unwrap();

            let mut stream = sock
                .connect(SocketAddr::from_str("100.100.100.100:2000").unwrap())
                .await
                .unwrap();
            // let mut stream = TcpStream::connect("100.100.100.100:2000").await.unwrap();

            log::info!("Established stream");

            let buf = vec![42; 2000];
            stream.write_all(&buf).await.unwrap();

            let t = SimTime::now();
            let d = SimTime::from_duration(Duration::from_secs(1)) - t;
            log::info!("Waiting for {d:?}");
            tokio::time::sleep(d).await;

            log::info!("Client done");
            drop(stream);
        });
    }

    async fn handle_message(&mut self, _: Message) {
        panic!()
    }
}

#[NdlSubsystem("bin")]
struct Main {}

fn main() {
    inet::init();

    ScopedLogger::new()
        .interal_max_log_level(log::LevelFilter::Warn)
        .finish()
        .unwrap();

    let app = Main {}.build_rt();
    let rt = Runtime::new_with(
        app,
        RuntimeOptions::seeded(123)
            // .max_itr(100)
            .max_time(SimTime::from_duration(Duration::from_secs(3))),
    );
    let _ = rt.run();
}
