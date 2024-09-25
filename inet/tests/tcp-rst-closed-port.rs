use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

use des::{prelude::*, registry, time::sleep};
use inet::{
    interface::{add_interface, Interface, NetworkDevice},
    *,
};
use tokio::spawn;

#[derive(Default)]
struct OneAttemptClient {
    done: Arc<AtomicBool>,
}

impl Module for OneAttemptClient {
    fn at_sim_start(&mut self, _: usize) {
        add_interface(Interface::ethv4(
            NetworkDevice::eth(),
            Ipv4Addr::new(69, 0, 0, 100),
        ))
        .unwrap();

        let done = self.done.clone();
        spawn(async move {
            let sock = TcpStream::connect("69.0.0.69:8000").await;
            tracing::info!("{:?}", sock);
            assert!(sock.is_err());
            done.store(true, Ordering::SeqCst);
        });
    }

    fn at_sim_end(&mut self) {
        assert!(self.done.load(Ordering::SeqCst));
    }
}

#[derive(Default)]
struct MultipleAttemptClient<const EXPECT: bool> {
    done: Arc<AtomicBool>,
}

impl<const EXPECT: bool> Module for MultipleAttemptClient<EXPECT> {
    fn at_sim_start(&mut self, _: usize) {
        add_interface(Interface::ethv4(
            NetworkDevice::eth(),
            Ipv4Addr::new(69, 0, 0, 100),
        ))
        .unwrap();

        let done = self.done.clone();
        spawn(async move {
            let addrs: [SocketAddr; 3] = [
                "69.0.0.69:8000".parse().unwrap(),
                "69.0.0.69:9000".parse().unwrap(),
                "69.0.0.69:10000".parse().unwrap(),
            ];
            let sock = TcpStream::connect(&addrs[..]).await;
            tracing::info!("{:?}", sock);
            assert_eq!(sock.is_ok(), EXPECT);
            done.store(true, Ordering::SeqCst);
        });
    }

    fn at_sim_end(&mut self) {
        assert!(self.done.load(Ordering::SeqCst));
    }
}

#[derive(Default)]
struct EmptyServer {}

impl Module for EmptyServer {
    fn at_sim_start(&mut self, _: usize) {
        add_interface(Interface::ethv4(
            NetworkDevice::eth(),
            Ipv4Addr::new(69, 0, 0, 69),
        ))
        .unwrap();
    }
}

#[derive(Default)]
struct BoundServer {}

impl Module for BoundServer {
    fn at_sim_start(&mut self, _: usize) {
        add_interface(Interface::ethv4(
            NetworkDevice::eth(),
            Ipv4Addr::new(69, 0, 0, 69),
        ))
        .unwrap();

        spawn(async move {
            let sock = TcpListener::bind("0.0.0.0:10000").await.unwrap();
            loop {
                let (stream, _) = sock.accept().await.unwrap();
                sleep(Duration::from_secs(1)).await;
                drop(stream);
            }
        });
    }
}

#[test]
#[serial_test::serial]
fn tcp_rst_for_closed_port() {
    type Server = EmptyServer;
    type Client = OneAttemptClient;

    // Logger::new().set_logger();

    let app = Sim::new(())
        .with_stack(inet::init)
        .with_ndl("tests/tcp2.yml", registry![Client, Server, else _])
        .map_err(|e| println!("{e}"))
        .unwrap();
    let rt = Builder::seeded(233).build(app);

    let _ = rt.run().unwrap();
}

#[test]
#[serial_test::serial]
fn tcp_rst_on_multiple_tries() {
    type Server = EmptyServer;
    type Client = MultipleAttemptClient<false>;

    // Logger::new().set_logger();

    let app = Sim::new(())
        .with_stack(inet::init)
        .with_ndl("tests/tcp2.yml", registry![Client, Server, else _])
        .map_err(|e| println!("{e}"))
        .unwrap();
    let rt = Builder::seeded(233).build(app);

    let _ = rt.run().unwrap();
}

#[test]
#[serial_test::serial]
fn tcp_rst_on_multiple_tries_with_success() {
    type Server = BoundServer;
    type Client = MultipleAttemptClient<true>;

    // Logger::new().set_logger();

    let app = Sim::new(())
        .with_stack(inet::init)
        .with_ndl("tests/tcp2.yml", registry![Client, Server, else _])
        .map_err(|e| println!("{e}"))
        .unwrap();
    let rt = Builder::seeded(233).build(app);

    let _ = rt.run().unwrap();
}
