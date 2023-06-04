use des::{prelude::*, registry, time::sleep};
use inet::{
    interface::{add_interface, Interface, NetworkDevice},
    *,
};
use tokio::{spawn, task::JoinHandle};

struct OneAttemptClient {
    handles: Vec<JoinHandle<()>>,
}
#[async_trait::async_trait]
impl AsyncModule for OneAttemptClient {
    fn new() -> Self {
        Self {
            handles: Vec::new(),
        }
    }

    async fn at_sim_start(&mut self, _: usize) {
        add_interface(Interface::ethv4(
            NetworkDevice::eth(),
            Ipv4Addr::new(69, 0, 0, 100),
        ))
        .unwrap();

        self.handles.push(spawn(async move {
            let sock = TcpStream::connect("69.0.0.69:8000").await;
            tracing::info!("{:?}", sock);
            assert!(sock.is_err());
        }));
    }

    async fn at_sim_end(&mut self) {
        for h in self.handles.drain(..) {
            h.await.unwrap();
        }
    }
}

struct MultipleAttemptClient<const EXPECT: bool> {
    handles: Vec<JoinHandle<()>>,
}
#[async_trait::async_trait]
impl<const EXPECT: bool> AsyncModule for MultipleAttemptClient<EXPECT> {
    fn new() -> Self {
        Self {
            handles: Vec::new(),
        }
    }

    async fn at_sim_start(&mut self, _: usize) {
        add_interface(Interface::ethv4(
            NetworkDevice::eth(),
            Ipv4Addr::new(69, 0, 0, 100),
        ))
        .unwrap();

        self.handles.push(spawn(async move {
            let addrs: [SocketAddr; 3] = [
                "69.0.0.69:8000".parse().unwrap(),
                "69.0.0.69:9000".parse().unwrap(),
                "69.0.0.69:10000".parse().unwrap(),
            ];
            let sock = TcpStream::connect(&addrs[..]).await;
            tracing::info!("{:?}", sock);
            assert_eq!(sock.is_ok(), EXPECT);
        }));
    }

    async fn at_sim_end(&mut self) {
        for h in self.handles.drain(..) {
            h.await.unwrap();
        }
    }
}

struct EmptyServer {}
#[async_trait::async_trait]
impl AsyncModule for EmptyServer {
    fn new() -> Self {
        Self {}
    }

    async fn at_sim_start(&mut self, _: usize) {
        add_interface(Interface::ethv4(
            NetworkDevice::eth(),
            Ipv4Addr::new(69, 0, 0, 69),
        ))
        .unwrap();
    }
}

struct BoundServer {}
#[async_trait::async_trait]
impl AsyncModule for BoundServer {
    fn new() -> Self {
        Self {}
    }

    async fn at_sim_start(&mut self, _: usize) {
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

struct Main;
impl Module for Main {
    fn new() -> Self {
        Self
    }
}

#[test]
#[serial_test::serial]
fn tcp_rst_for_closed_port() {
    inet::init();

    type Server = EmptyServer;
    type Client = OneAttemptClient;

    // Logger::new().set_logger();

    let app = NdlApplication::new("tests/tcp2.ndl", registry![Client, Server, Main])
        .map_err(|e| println!("{e}"))
        .unwrap();
    let app = NetworkApplication::new(app);
    let rt = Runtime::new_with(app, RuntimeOptions::seeded(233));

    let _ = rt.run().unwrap();
}

#[test]
#[serial_test::serial]
fn tcp_rst_on_multiple_tries() {
    inet::init();

    type Server = EmptyServer;
    type Client = MultipleAttemptClient<false>;

    // Logger::new().set_logger();

    let app = NdlApplication::new("tests/tcp2.ndl", registry![Client, Server, Main])
        .map_err(|e| println!("{e}"))
        .unwrap();
    let app = NetworkApplication::new(app);
    let rt = Runtime::new_with(app, RuntimeOptions::seeded(233));

    let _ = rt.run().unwrap();
}

#[test]
#[serial_test::serial]
fn tcp_rst_on_multiple_tries_with_success() {
    inet::init();

    type Server = BoundServer;
    type Client = MultipleAttemptClient<true>;

    // Logger::new().set_logger();

    let app = NdlApplication::new("tests/tcp2.ndl", registry![Client, Server, Main])
        .map_err(|e| println!("{e}"))
        .unwrap();
    let app = NetworkApplication::new(app);
    let rt = Runtime::new_with(app, RuntimeOptions::seeded(233));

    let _ = rt.run().unwrap();
}
