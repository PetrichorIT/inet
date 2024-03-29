use std::{collections::VecDeque, str::FromStr, sync::atomic::AtomicBool};

use des::{net::AsyncFn, prelude::*};
use inet::{
    interface::*,
    ipv6::{api::set_node_cfg, cfg::HostConfiguration},
    socket::RawIpSocket,
    *,
};
use serial_test::serial;
use tokio::task::JoinHandle;
use types::ip::{IpPacket, Ipv6AddrExt, Ipv6Packet};

#[derive(Default)]
struct SocketBind {
    handle: Option<JoinHandle<()>>,
}

impl AsyncModule for SocketBind {
    async fn at_sim_start(&mut self, _: usize) {
        add_interface(Interface::loopback()).unwrap();

        self.handle = Some(tokio::spawn(async move {
            let sock0 = UdpSocket::bind("0.0.0.0:0").await.unwrap();
            let device = sock0.device().unwrap();
            assert_eq!(device, Some(InterfaceName::new("lo0")));
            let addr = sock0.local_addr().unwrap();
            assert_eq!(addr, SocketAddr::from_str("0.0.0.0:1024").unwrap());
            let _peer = sock0.peer_addr().unwrap_err();
            drop(sock0);

            let sock1 = UdpSocket::bind("0.0.0.0:0").await.unwrap();
            let device = sock1.device().unwrap();
            assert_eq!(device, Some(InterfaceName::new("lo0")));
            let addr = sock1.local_addr().unwrap();
            assert_eq!(addr, SocketAddr::from_str("0.0.0.0:1025").unwrap());
            let _peer = sock1.peer_addr().unwrap_err();

            let sock2 = UdpSocket::bind("0.0.0.0:1024").await.unwrap();
            let device = sock2.device().unwrap();
            assert_eq!(device, Some(InterfaceName::new("lo0")));
            let addr = sock2.local_addr().unwrap();
            assert_eq!(addr, SocketAddr::from_str("0.0.0.0:1024").unwrap());
            let _peer = sock2.peer_addr().unwrap_err();
            drop(sock2);

            let _ = UdpSocket::bind("0.0.0.0:1025").await.unwrap_err();

            let sock3 = UdpSocket::bind("0.0.0.0:1026").await.unwrap();
            let device = sock3.device().unwrap();
            assert_eq!(device, Some(InterfaceName::new("lo0")));
            let addr = sock3.local_addr().unwrap();
            assert_eq!(addr, SocketAddr::from_str("0.0.0.0:1026").unwrap());
            let _peer = sock3.peer_addr().unwrap_err();

            let sock4 = UdpSocket::bind("0.0.0.0:0").await.unwrap();
            let device = sock4.device().unwrap();
            assert_eq!(device, Some(InterfaceName::new("lo0")));
            let addr = sock4.local_addr().unwrap();
            assert_eq!(addr, SocketAddr::from_str("0.0.0.0:1027").unwrap());
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
    // des::tracing::init();

    let mut app = Sim::new(());
    app.node("root", SocketBind::default());

    let rt = Builder::seeded(123).build(app);
    let _ = rt.run();
}

#[derive(Default)]
struct UdpEcho4200;

impl AsyncModule for UdpEcho4200 {
    async fn at_sim_start(&mut self, _: usize) {
        add_interface(Interface::ethv4_named(
            "en0",
            NetworkDevice::eth(),
            Ipv4Addr::new(1, 1, 1, 42),
            Ipv4Addr::new(255, 255, 255, 0),
        ))
        .unwrap();

        tokio::spawn(async move {
            let socket = UdpSocket::bind("0.0.0.0:42").await.unwrap();
            let mut buf = [0u8; 1024];
            loop {
                let Ok((n, src)) = socket.recv_from(&mut buf).await else {
                    tracing::error!("echo server got recv error");
                    continue;
                };

                tracing::info!("Echoing {} bytes to {}", n, src);

                if let Err(_) = socket.send_to(&buf[..n], src).await {
                    tracing::error!("echo server got sen error");
                }
            }
        });
    }
    async fn handle_message(&mut self, _: Message) {
        panic!("should only direct to udp socket");
    }
}

#[derive(Default)]
struct UdpSingleEchoSender {
    handle: Option<JoinHandle<()>>,
}

impl AsyncModule for UdpSingleEchoSender {
    async fn at_sim_start(&mut self, _: usize) {
        add_interface(Interface::ethv4_named(
            "en0",
            NetworkDevice::eth(),
            Ipv4Addr::new(1, 1, 1, 1),
            Ipv4Addr::new(255, 255, 255, 0),
        ))
        .unwrap();

        self.handle = Some(tokio::spawn(async move {
            let sock = UdpSocket::bind("0.0.0.0:0").await.unwrap();
            sock.connect("1.1.1.42:42").await.unwrap();

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

    // Logger::new().set_logger();

    let mut app = Sim::new(());
    app.node("server", UdpEcho4200::default());
    app.node("client", UdpSingleEchoSender::default());

    let so = app.gate("server", "port");
    let co = app.gate("client", "port");

    let chan = Channel::new(ChannelMetrics::new(
        100000,
        Duration::from_millis(100),
        Duration::ZERO,
        Default::default(),
    ));

    so.connect(co, Some(chan));

    let rt = Builder::seeded(123).build(app);
    let RuntimeResult::Finished { time, .. } = rt.run() else {
        panic!("Unexpected runtime result")
    };

    assert_eq!(time.as_secs(), 31)
}

#[derive(Default)]
struct UdpSingleClusteredSender {
    handle: Option<JoinHandle<()>>,
}

impl AsyncModule for UdpSingleClusteredSender {
    async fn at_sim_start(&mut self, _: usize) {
        add_interface(Interface::ethv4_named(
            "en0",
            NetworkDevice::eth(),
            Ipv4Addr::new(1, 1, 1, 1),
            Ipv4Addr::new(255, 255, 255, 0),
        ))
        .unwrap();

        self.handle = Some(tokio::spawn(async move {
            let sock = UdpSocket::bind("0.0.0.0:0").await.unwrap();
            sock.connect("1.1.1.42:42").await.unwrap();

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
    // Logger::new().set_logger();

    let mut app = Sim::new(());
    app.node("server", UdpEcho4200::default());
    app.node("client", UdpSingleClusteredSender::default());

    let so = app.gate("server", "port");
    let co = app.gate("client", "port");

    let chan = Channel::new(ChannelMetrics::new(
        100000,
        Duration::from_millis(100),
        Duration::ZERO,
        Default::default(),
    ));

    so.connect(co, Some(chan));

    let rt = Builder::seeded(123).build(app);
    let RuntimeResult::Finished { time, .. } = rt.run() else {
        panic!("Unexpected runtime result")
    };

    assert_eq!(time.as_secs(), 8)
}

#[derive(Default)]
struct UdpConcurrentClients {
    handle: Option<JoinHandle<()>>,
}

impl AsyncModule for UdpConcurrentClients {
    async fn at_sim_start(&mut self, _: usize) {
        add_interface(Interface::ethv4_named(
            "en0",
            NetworkDevice::eth(),
            Ipv4Addr::new(1, 1, 1, 1),
            Ipv4Addr::new(255, 255, 255, 0),
        ))
        .unwrap();

        self.handle = Some(tokio::spawn(async move {
            let h1 = tokio::spawn(async move {
                let sock = UdpSocket::bind("0.0.0.0:0").await.unwrap();
                sock.connect("1.1.1.42:42").await.unwrap();

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
                sock.connect("1.1.1.42:42").await.unwrap();

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
                    let n = sock.send_to(&msg, "1.1.1.42:42").await.unwrap();
                    assert_eq!(n, size);

                    let mut buf = [0u8; 1024];
                    let (n, from) = sock.recv_from(&mut buf).await.unwrap();
                    assert_eq!(from, SocketAddr::from_str("1.1.1.42:42").unwrap());
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

    let mut app = Sim::new(());
    app.node("server", UdpEcho4200::default());
    app.node("client", UdpConcurrentClients::default());

    let so = app.gate("server", "port");
    let co = app.gate("client", "port");

    let chan = Channel::new(ChannelMetrics::new(
        100000,
        Duration::from_millis(100),
        Duration::ZERO,
        Default::default(),
    ));

    so.connect(co, Some(chan));

    let rt = Builder::seeded(123).build(app);
    let RuntimeResult::Finished { time, .. } = rt.run() else {
        panic!("Unexpected runtime result")
    };

    assert_eq!(time.as_secs(), 32)
}

#[test]
#[serial]
fn interface_does_not_use_busy_channel() {
    inet::init();
    // des::tracing::init();

    static DONE: AtomicBool = AtomicBool::new(false);

    let mut sim = Sim::new(());
    sim.node(
        "sender",
        AsyncFn::failable::<_, _, std::io::Error>(|_| async move {
            set_node_cfg(HostConfiguration {
                dup_addr_detect_transmits: 0,
            })?;
            add_interface(Interface::empty("en0", NetworkDevice::eth()))?;

            // Sleep to prevent MLD messags from blocking the sender
            des::time::sleep(Duration::from_secs(1)).await;

            for i in 0..32 {
                send(Message::new().id(i).build(), "port");
            }

            let sock = RawIpSocket::new_v6()?;
            sock.try_send(IpPacket::V6(Ipv6Packet {
                traffic_class: 0,
                flow_label: 0,
                next_header: 42,
                hop_limit: 32,
                src: Ipv6Addr::UNSPECIFIED,
                dst: Ipv6Addr::MULTICAST_ALL_NODES,
                content: Vec::new(),
            }))?;

            for i in 0..32 {
                send(Message::new().id(32 + i).build(), "port");
            }

            Ok(())
        }),
    );

    sim.node(
        "receiver",
        AsyncFn::failable::<_, _, std::io::Error>(|mut rx| async move {
            set_node_cfg(HostConfiguration {
                dup_addr_detect_transmits: 0,
            })?;
            add_interface(Interface::empty("en0", NetworkDevice::eth()))?;

            let mut count = 0;
            let mut sock = RawIpSocket::new_v6()?;
            sock.bind_proto(42)?;
            loop {
                tokio::select! {
                    pkt = sock.recv() => {
                        let pkt = pkt.unwrap();
                        if pkt.tos() != 58 {
                            assert_eq!(count, 64);
                            DONE.store(true, std::sync::atomic::Ordering::SeqCst);
                            break;
                        }
                    }
                    _ = rx.recv() => {
                        count += 1;
                    }
                };
            }

            Ok(())
        }),
    );

    let tx = sim.gate("sender", "port");
    let rx = sim.gate("receiver", "port");

    tx.connect(
        rx,
        Some(Channel::new(ChannelMetrics {
            bitrate: 1000_000,
            latency: Duration::from_millis(20),
            jitter: Duration::ZERO,
            drop_behaviour: ChannelDropBehaviour::Queue(None),
        })),
    );

    let rt = Builder::seeded(123).build(sim);
    let _ = rt.run();

    assert!(DONE.load(std::sync::atomic::Ordering::SeqCst));
}

#[test]
#[serial]
fn interface_will_use_idle_channel_fcfs() {
    inet::init();
    // des::tracing::init();

    static DONE: AtomicBool = AtomicBool::new(false);

    let mut sim = Sim::new(());
    sim.node(
        "sender",
        AsyncFn::failable::<_, _, std::io::Error>(|_| async move {
            set_node_cfg(HostConfiguration {
                dup_addr_detect_transmits: 0,
            })?;
            add_interface(Interface::empty("en0", NetworkDevice::eth()))?;

            // Sleep to prevent MLD messags from blocking the sender
            des::time::sleep(Duration::from_secs(1)).await;

            let sock = RawIpSocket::new_v6()?;
            sock.try_send(IpPacket::V6(Ipv6Packet {
                traffic_class: 0,
                flow_label: 0,
                next_header: 42,
                hop_limit: 32,
                src: Ipv6Addr::UNSPECIFIED,
                dst: Ipv6Addr::MULTICAST_ALL_NODES,
                content: Vec::new(),
            }))?;

            for i in 0..32 {
                send(Message::new().id(32 + i).build(), "port");
            }

            Ok(())
        }),
    );

    sim.node(
        "receiver",
        AsyncFn::failable::<_, _, std::io::Error>(|mut rx| async move {
            set_node_cfg(HostConfiguration {
                dup_addr_detect_transmits: 0,
            })?;
            add_interface(Interface::empty("en0", NetworkDevice::eth()))?;

            let mut count = 0;
            let mut sock = RawIpSocket::new_v6()?;
            sock.bind_proto(42)?;
            loop {
                tokio::select! {
                    pkt = sock.recv() => {
                        let pkt = pkt.unwrap();
                        if pkt.tos() != 58 {
                            assert_eq!(count, 0);

                        }
                    }
                    _ = rx.recv() => {
                        count += 1;
                        if count == 32 {
                            DONE.store(true, std::sync::atomic::Ordering::SeqCst);
                            break;
                        }
                    }
                };
            }

            Ok(())
        }),
    );

    let so = sim.gate("sender", "port");
    let co = sim.gate("receiver", "port");

    so.connect(
        co,
        Some(Channel::new(ChannelMetrics {
            bitrate: 1000_000,
            latency: Duration::from_millis(20),
            jitter: Duration::ZERO,
            drop_behaviour: ChannelDropBehaviour::Queue(None),
        })),
    );

    let rt = Builder::seeded(123).build(sim);
    let _ = rt.run();

    assert!(DONE.load(std::sync::atomic::Ordering::SeqCst));
}
