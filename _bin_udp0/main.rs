use des::prelude::*;
use inet::inet::{add_interface, Interface, NetworkDevice, UdpSocket};

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
            let sock = UdpSocket::bind("[::0]:2000").await.unwrap();
            loop {
                let mut buf = [0u8; 512];
                let (n, src) = sock.recv_from(&mut buf).await.unwrap();
                log::info!("Received {} bytes from {}", n, src);
                sock.send_to(&buf[..n], src).await.unwrap();
            }
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
            let sock = UdpSocket::bind("[::0]:1000").await.unwrap();
            sock.connect("[::100.100.100.100]:2000").await.unwrap();

            sock.send(&vec![42u8; 100]).await.unwrap();
            sock.send(&vec![69u8; 300]).await.unwrap();

            let mut buf = [0u8; 512];
            sock.recv(&mut buf).await.unwrap();
            log::info!("First: {:?}", &buf[..10]);

            let mut buf = [0u8; 512];
            sock.recv(&mut buf).await.unwrap();
            log::info!("Second: {:?}", &buf[..10]);
        });

        tokio::spawn(async move {
            let sock = UdpSocket::bind("[::0]:3000").await.unwrap();
            sock.connect("[::100.100.100.100]:2000").await.unwrap();

            sock.send(&vec![142u8; 200]).await.unwrap();
            sock.send(&vec![169u8; 150]).await.unwrap();

            let mut buf = [0u8; 512];
            sock.recv(&mut buf).await.unwrap();
            log::info!("First: {:?}", &buf[..10]);

            let mut buf = [0u8; 512];
            sock.recv(&mut buf).await.unwrap();
            log::info!("Second: {:?}", &buf[..10]);
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

    // Should complete at 365.184001ms
    // -> 1.364358401s due to timeouts
}
