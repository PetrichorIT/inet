use des::prelude::*;
use inet::inet::{add_interface, Interface, NetworkDevice, TcpListener, TcpStream};

#[NdlModule("bin")]
struct A {}
#[async_trait::async_trait]
impl AsyncModule for A {
    fn new() -> Self {
        Self {}
    }

    async fn at_sim_start(&mut self, _: usize) {
        add_interface(Interface::en0(
            random(),
            Ipv4Addr::new(100, 100, 100, 100),
            NetworkDevice::eth_default(),
        ));

        tokio::spawn(async move {
            let sock = TcpListener::bind("[::0]:2000").await.unwrap();

            let (stream, _) = sock.accept().await.unwrap();
            log::info!("Established stream");
            let _ = stream;
        });
    }

    async fn handle_message(&mut self, _: Message) {
        panic!()
    }
}

#[NdlModule("bin")]
struct B {}
#[async_trait::async_trait]
impl AsyncModule for B {
    fn new() -> Self {
        Self {}
    }

    async fn at_sim_start(&mut self, _: usize) {
        add_interface(Interface::en0(
            random(),
            Ipv4Addr::new(200, 200, 200, 200),
            NetworkDevice::eth_default(),
        ));

        tokio::spawn(async move {
            let _stream = TcpStream::connect("[::100.100.100.100]:2000")
                .await
                .unwrap();

            log::info!("Established stream");
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
