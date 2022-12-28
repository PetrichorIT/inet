use std::{collections::VecDeque, str::FromStr};

use async_trait::async_trait;
use des::{
    net::{BuildContext, __Buildable0},
    prelude::*,
};
use inet::inet::{interface::*, *};
use serial_test::serial;
use tokio::task::JoinHandle;

#[NdlModule]
struct SocketBind {
    handle: Option<JoinHandle<()>>,
}

#[async_trait]
impl AsyncModule for SocketBind {
    fn new() -> Self {
        Self { handle: None }
    }

    async fn at_sim_start(&mut self, _: usize) {
        add_interface(Interface::loopback());

        self.handle = Some(tokio::spawn(async move {
            let sock0 = UdpSocket::bind("0.0.0.0:0").await.unwrap();
            let device = sock0.device().unwrap();
            assert_eq!(device, Some(InterfaceName::new("lo0")));
            let addr = sock0.local_addr().unwrap();
            assert_eq!(addr, SocketAddr::from_str("127.0.0.1:1024").unwrap());
            let _peer = sock0.peer_addr().unwrap_err();
            drop(sock0);

            let sock1 = UdpSocket::bind("0.0.0.0:0").await.unwrap();
            let device = sock1.device().unwrap();
            assert_eq!(device, Some(InterfaceName::new("lo0")));
            let addr = sock1.local_addr().unwrap();
            assert_eq!(addr, SocketAddr::from_str("127.0.0.1:1025").unwrap());
            let _peer = sock1.peer_addr().unwrap_err();

            let sock2 = UdpSocket::bind("0.0.0.0:1024").await.unwrap();
            let device = sock2.device().unwrap();
            assert_eq!(device, Some(InterfaceName::new("lo0")));
            let addr = sock2.local_addr().unwrap();
            assert_eq!(addr, SocketAddr::from_str("127.0.0.1:1024").unwrap());
            let _peer = sock2.peer_addr().unwrap_err();
            drop(sock2);

            let _ = UdpSocket::bind("0.0.0.0:1025").await.unwrap_err();

            let sock3 = UdpSocket::bind("0.0.0.0:1026").await.unwrap();
            let device = sock3.device().unwrap();
            assert_eq!(device, Some(InterfaceName::new("lo0")));
            let addr = sock3.local_addr().unwrap();
            assert_eq!(addr, SocketAddr::from_str("127.0.0.1:1026").unwrap());
            let _peer = sock3.peer_addr().unwrap_err();

            let sock4 = UdpSocket::bind("0.0.0.0:0").await.unwrap();
            let device = sock4.device().unwrap();
            assert_eq!(device, Some(InterfaceName::new("lo0")));
            let addr = sock4.local_addr().unwrap();
            assert_eq!(addr, SocketAddr::from_str("127.0.0.1:1027").unwrap());
            let _peer = sock4.peer_addr().unwrap_err();

            drop((sock1, sock3, sock4))
        }))
    }

    async fn at_sim_end(&mut self) {
        self.handle.take().unwrap().await.unwrap();
    }
}

#[test]
#[serial]
fn udp_empty_socket_bind() {
    inet::init();
    // ScopedLogger::new().finish().unwrap();

    let mut app = NetworkRuntime::new(());
    let mut cx = BuildContext::new(&mut app);

    let module = SocketBind::build_named(ObjectPath::root_module("root"), &mut cx);
    cx.create_module(module);

    let rt = Runtime::new_with(app, RuntimeOptions::seeded(123));
    let RuntimeResult::Finished { .. } = rt.run() else {
        panic!("Unexpected runtime result")
    };
}

#[NdlModule]
struct UdpEcho4200 {}

#[async_trait]
impl AsyncModule for UdpEcho4200 {
    fn new() -> Self {
        Self {}
    }
    async fn at_sim_start(&mut self, _: usize) {
        add_interface(Interface::en0(
            random(),
            Ipv4Addr::new(42, 42, 42, 42),
            NetworkDevice::eth_default(),
        ));

        tokio::spawn(async move {
            let socket = UdpSocket::bind("0.0.0.0:42").await.unwrap();
            let mut buf = [0u8; 1024];
            loop {
                let Ok((n, src)) = socket.recv_from(&mut buf).await else {
                    log::error!("echo server got recv error");
                    continue
                };

                log::info!("Echoing {} bytes to {}", n, src);

                if let Err(_) = socket.send_to(&buf[..n], src).await {
                    log::error!("echo server got sen error");
                }
            }
        });
    }
    async fn handle_message(&mut self, _: Message) {
        panic!("should only direct to udp socket");
    }
}

#[NdlModule]
struct UdpSingleEchoSender {
    handle: Option<JoinHandle<()>>,
}

#[async_trait]
impl AsyncModule for UdpSingleEchoSender {
    fn new() -> Self {
        Self { handle: None }
    }

    async fn at_sim_start(&mut self, _: usize) {
        add_interface(Interface::en0(
            random(),
            Ipv4Addr::new(1, 1, 1, 1),
            NetworkDevice::eth_default(),
        ));

        self.handle = Some(tokio::spawn(async move {
            let sock = UdpSocket::bind("0.0.0.0:0").await.unwrap();
            sock.connect("42.42.42.42:42").await.unwrap();

            for _ in 0..100 {
                let size = random::<usize>() % 800 + 200;
                let msg = std::iter::from_fn(|| Some(random::<u8>()))
                    .take(size)
                    .collect::<Vec<_>>();
                let n = sock.send(&msg).await.unwrap();
                assert_eq!(n, size);

                let mut buf = [0u8; 1024];
                let n = sock.recv(&mut buf).await.unwrap();
                assert_eq!(n, size);
                assert_eq!(&buf[..n], &msg[..]);
            }
        }))
    }

    async fn at_sim_end(&mut self) {
        self.handle.take().unwrap().await.unwrap();
    }
}

#[test]
#[serial]
fn udp_echo_single_client() {
    inet::init();
    // ScopedLogger::new()
    //     .interal_max_log_level(log::LevelFilter::Warn)
    //     .finish()
    //     .unwrap();

    let mut app = NetworkRuntime::new(());
    let mut cx = BuildContext::new(&mut app);

    let server = UdpEcho4200::build_named(ObjectPath::root_module("server"), &mut cx);
    let client = UdpSingleEchoSender::build_named(ObjectPath::root_module("client"), &mut cx);

    let so = server.create_gate("out", GateServiceType::Output);
    let si = server.create_gate("in", GateServiceType::Input);
    let co = client.create_gate("out", GateServiceType::Output);
    let ci = client.create_gate("in", GateServiceType::Input);

    so.set_next_gate(ci);
    co.set_next_gate(si);

    let cschan = Channel::new(
        ObjectPath::channel_with("upstream", &client.path()),
        ChannelMetrics::new(100000, Duration::from_millis(100), Duration::ZERO),
    );
    let scchan = Channel::new(
        ObjectPath::channel_with("downstream", &server.path()),
        ChannelMetrics::new(100000, Duration::from_millis(100), Duration::ZERO),
    );

    co.set_channel(cschan);
    so.set_channel(scchan);

    cx.create_module(server);
    cx.create_module(client);

    let rt = Runtime::new_with(app, RuntimeOptions::seeded(123));
    let RuntimeResult::Finished { time, .. } = rt.run() else {
        panic!("Unexpected runtime result")
    };

    assert_eq!(time.as_secs(), 31)
}

#[NdlModule]
struct UdpSingleClusteredSender {
    handle: Option<JoinHandle<()>>,
}

#[async_trait]
impl AsyncModule for UdpSingleClusteredSender {
    fn new() -> Self {
        Self { handle: None }
    }

    async fn at_sim_start(&mut self, _: usize) {
        add_interface(Interface::en0(
            random(),
            Ipv4Addr::new(1, 1, 1, 1),
            NetworkDevice::eth_default(),
        ));

        self.handle = Some(tokio::spawn(async move {
            let sock = UdpSocket::bind("0.0.0.0:0").await.unwrap();
            sock.connect("42.42.42.42:42").await.unwrap();

            let mut msgs = VecDeque::new();

            for i in 0..103 {
                if i < 100 {
                    let size = random::<usize>() % 800 + 200;
                    let msg = std::iter::from_fn(|| Some(random::<u8>()))
                        .take(size)
                        .collect::<Vec<_>>();
                    let n = sock.send(&msg).await.unwrap();
                    assert_eq!(n, size);
                    msgs.push_back(msg);
                }

                if i >= 3 {
                    let expected = msgs.pop_front().unwrap();

                    let mut buf = [0u8; 1024];
                    let n = sock.recv(&mut buf).await.unwrap();
                    assert_eq!(n, expected.len());
                    assert_eq!(&buf[..n], &expected[..]);
                }
            }
        }))
    }

    async fn at_sim_end(&mut self) {
        self.handle.take().unwrap().await.unwrap();
    }
}

#[test]
#[serial]
fn udp_echo_clustered_echo() {
    inet::init();
    // ScopedLogger::new()
    //     .interal_max_log_level(log::LevelFilter::Warn)
    //     .finish()
    //     .unwrap();

    let mut app = NetworkRuntime::new(());
    let mut cx = BuildContext::new(&mut app);

    let server = UdpEcho4200::build_named(ObjectPath::root_module("server"), &mut cx);
    let client = UdpSingleClusteredSender::build_named(ObjectPath::root_module("client"), &mut cx);

    let so = server.create_gate("out", GateServiceType::Output);
    let si = server.create_gate("in", GateServiceType::Input);
    let co = client.create_gate("out", GateServiceType::Output);
    let ci = client.create_gate("in", GateServiceType::Input);

    so.set_next_gate(ci);
    co.set_next_gate(si);

    let cschan = Channel::new(
        ObjectPath::channel_with("upstream", &client.path()),
        ChannelMetrics::new(100000, Duration::from_millis(100), Duration::ZERO),
    );
    let scchan = Channel::new(
        ObjectPath::channel_with("downstream", &server.path()),
        ChannelMetrics::new(100000, Duration::from_millis(100), Duration::ZERO),
    );

    co.set_channel(cschan);
    so.set_channel(scchan);

    cx.create_module(server);
    cx.create_module(client);

    let rt = Runtime::new_with(app, RuntimeOptions::seeded(123));
    let RuntimeResult::Finished { time, .. } = rt.run() else {
        panic!("Unexpected runtime result")
    };

    assert_eq!(time.as_secs(), 8)
}

#[NdlModule]
struct UdpConcurrentClients {
    handle: Option<JoinHandle<()>>,
}

#[async_trait]
impl AsyncModule for UdpConcurrentClients {
    fn new() -> Self {
        Self { handle: None }
    }

    async fn at_sim_start(&mut self, _: usize) {
        add_interface(Interface::en0(
            random(),
            Ipv4Addr::new(1, 1, 1, 1),
            NetworkDevice::eth_default(),
        ));

        self.handle = Some(tokio::spawn(async move {
            let h1 = tokio::spawn(async move {
                let sock = UdpSocket::bind("0.0.0.0:0").await.unwrap();
                sock.connect("42.42.42.42:42").await.unwrap();

                for _ in 0..100 {
                    let size = random::<usize>() % 800 + 200;
                    let msg = std::iter::from_fn(|| Some(random::<u8>()))
                        .take(size)
                        .collect::<Vec<_>>();
                    let n = sock.send(&msg).await.unwrap();
                    assert_eq!(n, size);

                    let mut buf = [0u8; 1024];
                    let n = sock.recv(&mut buf).await.unwrap();
                    assert_eq!(n, size);
                    assert_eq!(&buf[..n], &msg[..]);
                }
            });
            let h2 = tokio::spawn(async move {
                let sock = UdpSocket::bind("0.0.0.0:0").await.unwrap();
                sock.connect("42.42.42.42:42").await.unwrap();

                for _ in 0..100 {
                    let size = random::<usize>() % 800 + 200;
                    let msg = std::iter::from_fn(|| Some(random::<u8>()))
                        .take(size)
                        .collect::<Vec<_>>();
                    let n = sock.send(&msg).await.unwrap();
                    assert_eq!(n, size);

                    let mut buf = [0u8; 1024];
                    let n = sock.recv(&mut buf).await.unwrap();
                    assert_eq!(n, size);
                    assert_eq!(&buf[..n], &msg[..]);
                }
            });
            let h3 = tokio::spawn(async move {
                let sock = UdpSocket::bind("0.0.0.0:0").await.unwrap();

                for _ in 0..100 {
                    let size = random::<usize>() % 800 + 200;
                    let msg = std::iter::from_fn(|| Some(random::<u8>()))
                        .take(size)
                        .collect::<Vec<_>>();
                    let n = sock.send_to(&msg, "42.42.42.42:42").await.unwrap();
                    assert_eq!(n, size);

                    let mut buf = [0u8; 1024];
                    let (n, from) = sock.recv_from(&mut buf).await.unwrap();
                    assert_eq!(from, SocketAddr::from_str("42.42.42.42:42").unwrap());
                    assert_eq!(n, size);
                    assert_eq!(&buf[..n], &msg[..]);
                }
            });

            h1.await.unwrap();
            h2.await.unwrap();
            h3.await.unwrap();
        }))
    }

    async fn at_sim_end(&mut self) {
        self.handle.take().unwrap().await.unwrap();
    }
}

#[test]
#[serial]
fn udp_echo_concurrent_clients() {
    inet::init();
    // ScopedLogger::new()
    //     .interal_max_log_level(log::LevelFilter::Warn)
    //     .finish()
    //     .unwrap();

    let mut app = NetworkRuntime::new(());
    let mut cx = BuildContext::new(&mut app);

    let server = UdpEcho4200::build_named(ObjectPath::root_module("server"), &mut cx);
    let client = UdpConcurrentClients::build_named(ObjectPath::root_module("client"), &mut cx);

    let so = server.create_gate("out", GateServiceType::Output);
    let si = server.create_gate("in", GateServiceType::Input);
    let co = client.create_gate("out", GateServiceType::Output);
    let ci = client.create_gate("in", GateServiceType::Input);

    so.set_next_gate(ci);
    co.set_next_gate(si);

    let cschan = Channel::new(
        ObjectPath::channel_with("upstream", &client.path()),
        ChannelMetrics::new(100000, Duration::from_millis(100), Duration::ZERO),
    );
    let scchan = Channel::new(
        ObjectPath::channel_with("downstream", &server.path()),
        ChannelMetrics::new(100000, Duration::from_millis(100), Duration::ZERO),
    );

    co.set_channel(cschan);
    so.set_channel(scchan);

    cx.create_module(server);
    cx.create_module(client);

    let rt = Runtime::new_with(app, RuntimeOptions::seeded(123));
    let RuntimeResult::Finished { time, .. } = rt.run() else {
        panic!("Unexpected runtime result")
    };

    assert_eq!(time.as_secs(), 32)
}
