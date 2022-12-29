use std::io::ErrorKind;

use des::prelude::*;
use inet::inet::{interface::*, tcp::TcpDebugPlugin, TcpListener, TcpStream};

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
            let sock = TcpListener::bind("0.0.0.0:2000").await.unwrap();
            log::info!("Server bound");

            let (mut stream, _) = sock.accept().await.unwrap();
            log::info!("Established stream");

            let mut buf = [0u8; 100];
            let err = stream.try_read(&mut buf).unwrap_err();
            assert_eq!(err.kind(), ErrorKind::WouldBlock);

            use tokio::io::AsyncReadExt;
            let n = stream.read(&mut buf).await.unwrap();
            assert_eq!(n, 100);

            // read 3500 bytes
            let mut bytes = 0;
            while bytes < 3900 {
                let mut buf = [0u8; 500];
                let n = stream.read(&mut buf).await.unwrap();
                bytes += n;
                log::info!("Now consumed 100 + {bytes} bytes")
            }
            // assert_eq!(n, 300);

            let err = stream.try_read(&mut buf).unwrap_err();
            assert_eq!(err.kind(), ErrorKind::WouldBlock);

            log::info!("Sever done");
            std::mem::forget(stream);

            std::mem::forget(sock);
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
            let mut stream = TcpStream::connect("100.100.100.100:2000").await.unwrap();

            log::info!("Established stream");

            let buf = vec![42; 4000];
            stream.write_all(&buf).await.unwrap();
            // log::info!("wrotes {n}")
            log::info!("Client done");
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
    let rt = Runtime::new_with(app, RuntimeOptions::seeded(123));
    let _ = rt.run();
}
