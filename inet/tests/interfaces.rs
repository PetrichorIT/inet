use std::{
    collections::VecDeque,
    io::ErrorKind,
    str::FromStr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use bytes_io::Bytes;
use des::{net::handlers::AsyncHandler, prelude::*, time::sleep};
use inet::{
    interface::*,
    ipv6::{api::set_node_cfg, cfg::HostConfiguration},
    socket::RawIpSocket,
    *,
};
use serial_test::serial;
use types::{
    ip::{IpPacket, Ipv6AddrExt, Ipv6Packet},
    udp::PROTO_UDP,
};

#[derive(Default)]
struct SocketBind {
    done: Arc<AtomicBool>,
}

impl Module for SocketBind {
    fn at_sim_start(&mut self, _: usize) {
        ioctx().add_interface(InterfaceDef::loopback()).unwrap();

        let done = self.done.clone();
        tokio::spawn(async move {
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

            drop((sock1, sock3, sock4));
            done.store(true, Ordering::SeqCst)
        });
    }

    fn at_sim_end(&mut self) -> Result<(), RuntimeError> {
        assert!(self.done.load(Ordering::SeqCst));
        Ok(())
    }
}

#[test]
#[serial]
fn udp_empty_socket_bind() -> Result<(), RuntimeError> {
    // des::tracing::init();

    let mut app = Sim::new(()).with_stack(inet::init);
    app.node("root", SocketBind::default());

    let rt = Builder::seeded(123).build(app.freeze());
    rt.run().map(|_| ())
}

#[derive(Default)]
struct UdpEcho4200;

impl Module for UdpEcho4200 {
    fn at_sim_start(&mut self, _: usize) {
        ioctx()
            .add_interface(
                InterfaceDef::new("en0", NetworkDevice::eth())
                    .ip(Ipv4Addr::new(1, 1, 1, 42).into())
                    .ip(Ipv4Addr::new(255, 255, 255, 0).into()),
            )
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
    fn handle_message(&mut self, _: Message) {
        panic!("should only direct to udp socket");
    }
}

#[derive(Default)]
struct UdpSingleEchoSender {
    done: Arc<AtomicBool>,
}

impl Module for UdpSingleEchoSender {
    fn at_sim_start(&mut self, _: usize) {
        ioctx()
            .add_interface(
                InterfaceDef::new("en0", NetworkDevice::eth())
                    .ip(Ipv4Addr::new(1, 1, 1, 1).into())
                    .ip(Ipv4Addr::new(255, 255, 255, 0).into()),
            )
            .unwrap();

        let done = self.done.clone();
        tokio::spawn(async move {
            let sock = UdpSocket::bind("0.0.0.0:0").await.unwrap();
            sock.connect("1.1.1.42:42").await.unwrap();

            for _ in 0..100 {
                let size = random::<u64>() as usize % 800 + 200;
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
            done.store(true, Ordering::SeqCst)
        });
    }

    fn at_sim_end(&mut self) -> Result<(), RuntimeError> {
        assert!(self.done.load(Ordering::SeqCst));
        Ok(())
    }
}

#[test]
#[serial]
fn udp_echo_single_client() {
    // Logger::new().set_logger();

    let mut app = Sim::new(()).with_stack(inet::init);
    app.node("server", UdpEcho4200::default());
    app.node("client", UdpSingleEchoSender::default());

    let so = app.gate("server", "port");
    let co = app.gate("client", "port");

    let chan = DatarateChannel::new(DatarateChannelMetrics::new(
        100000,
        Duration::from_millis(100),
        Duration::ZERO,
        Default::default(),
    ));

    so.connect_with(co, Some(chan));

    let rt = Builder::seeded(123).build(app.freeze());
    let Ok((_, time, _)) = rt.run() else {
        panic!("Unexpected runtime result")
    };

    assert_eq!(time.as_secs(), 31);
}

#[derive(Default)]
struct UdpSingleClusteredSender {
    done: Arc<AtomicBool>,
}

impl Module for UdpSingleClusteredSender {
    fn at_sim_start(&mut self, _: usize) {
        ioctx()
            .add_interface(
                InterfaceDef::new("en0", NetworkDevice::eth())
                    .ip(Ipv4Addr::new(1, 1, 1, 1).into())
                    .ip(Ipv4Addr::new(255, 255, 255, 0).into()),
            )
            .unwrap();

        let done = self.done.clone();
        tokio::spawn(async move {
            let sock = UdpSocket::bind("0.0.0.0:0").await.unwrap();
            sock.connect("1.1.1.42:42").await.unwrap();

            let mut msgs = VecDeque::new();

            for i in 0..103 {
                if i < 100 {
                    let size = random::<u64>() as usize % 800 + 200;
                    let msg = std::iter::from_fn(|| Some(random::<u8>()))
                        .take(size)
                        .collect::<Vec<_>>();
                    tracing::info!("sending #{i} {size} bytes");
                    let n = sock.send(&msg).await.unwrap();
                    assert_eq!(n, size);
                    msgs.push_back(msg);
                }

                if i >= 3 {
                    let expected = msgs.pop_front().unwrap();

                    let mut buf = [0u8; 1024];
                    tracing::info!("try: receiving #{}", i - 3);
                    let n = sock.recv(&mut buf).await.unwrap();
                    assert_eq!(n, expected.len());
                    assert_eq!(&buf[..n], &expected[..]);
                }
            }
            done.store(true, Ordering::SeqCst)
        });
    }

    fn at_sim_end(&mut self) -> Result<(), RuntimeError> {
        assert!(self.done.load(Ordering::SeqCst));
        Ok(())
    }
}

#[test]
#[serial]
fn udp_echo_clustered_echo() {
    let mut app = Sim::new(()).with_stack(inet::init);
    app.node("server", UdpEcho4200::default());
    app.node("client", UdpSingleClusteredSender::default());

    let so = app.gate("server", "port");
    let co = app.gate("client", "port");

    let chan = DatarateChannel::new(DatarateChannelMetrics::new(
        100000,
        Duration::from_millis(100),
        Duration::ZERO,
        Default::default(),
    ));

    so.connect_with(co, Some(chan));

    let rt = Builder::seeded(123).build(app.freeze());
    let Ok((_, time, _)) = rt.run() else {
        panic!("Unexpected runtime result")
    };

    assert_eq!(time.as_secs(), 8)
}

#[derive(Default)]
struct UdpConcurrentClients {
    done: Arc<AtomicBool>,
}

impl Module for UdpConcurrentClients {
    fn at_sim_start(&mut self, _: usize) {
        ioctx()
            .add_interface(
                InterfaceDef::new("en0", NetworkDevice::eth())
                    .ip(Ipv4Addr::new(1, 1, 1, 1).into())
                    .ip(Ipv4Addr::new(255, 255, 255, 0).into()),
            )
            .unwrap();

        let done = self.done.clone();
        tokio::spawn(async move {
            let h1 = tokio::spawn(async move {
                let sock = UdpSocket::bind("0.0.0.0:0").await.unwrap();
                sock.connect("1.1.1.42:42").await.unwrap();

                for _ in 0..100 {
                    let size = random::<u64>() as usize % 800 + 200;
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
                    let size = random::<u64>() as usize % 800 + 200;
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
                    let size = random::<u64>() as usize % 800 + 200;
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
            done.store(true, Ordering::SeqCst)
        });
    }

    fn at_sim_end(&mut self) -> Result<(), RuntimeError> {
        assert!(self.done.load(Ordering::SeqCst));
        Ok(())
    }
}

#[test]
#[serial]
fn udp_echo_concurrent_clients() {
    let mut app = Sim::new(()).with_stack(inet::init);
    app.node("server", UdpEcho4200::default());
    app.node("client", UdpConcurrentClients::default());

    let so = app.gate("server", "port");
    let co = app.gate("client", "port");

    let chan = DatarateChannel::new(DatarateChannelMetrics::new(
        100000,
        Duration::from_millis(100),
        Duration::ZERO,
        Default::default(),
    ));

    so.connect_with(co, Some(chan));

    let rt = Builder::seeded(123).build(app.freeze());
    let Ok((_, time, _)) = rt.run() else {
        panic!("Unexpected runtime result")
    };

    assert_eq!(time.as_secs(), 32)
}

#[test]
#[serial]
fn interface_does_not_use_busy_channel() -> Result<(), RuntimeError> {
    // des::tracing::init();

    static DONE: AtomicBool = AtomicBool::new(false);

    let mut sim = Sim::new(()).with_stack(inet::init);
    sim.node(
        "sender",
        AsyncHandler::failable::<_, _, std::io::Error>(|_| async move {
            set_node_cfg(HostConfiguration {
                dup_addr_detect_for_link_local: false,
                dup_addr_detect_transmits: 0,
            })?;
            ioctx().add_interface(InterfaceDef::new("en0", NetworkDevice::eth()).v6())?;

            // Sleep to prevent MLD messags from blocking the sender
            des::time::sleep(Duration::from_secs(1)).await;

            for i in 0..32 {
                send(Message::default().with_id(i), "port").unwrap();
            }

            let sock = RawIpSocket::new_v6()?;
            sock.try_send(IpPacket::V6(Ipv6Packet {
                traffic_class: 0,
                flow_label: 0,
                proto: 42,
                hop_limit: 32,
                extension_headers: Vec::new(),
                src: Ipv6Addr::UNSPECIFIED,
                dst: Ipv6Addr::MULTICAST_ALL_NODES,
                content: Bytes::new(),
            }))?;

            for i in 0..32 {
                send(Message::default().with_id(32 + i), "port").unwrap();
            }

            Ok(())
        }),
    );

    sim.node(
        "receiver",
        AsyncHandler::failable::<_, _, std::io::Error>(|mut rx| async move {
            set_node_cfg(HostConfiguration {
                dup_addr_detect_for_link_local: false,
                dup_addr_detect_transmits: 0,
            })?;
            ioctx().add_interface(InterfaceDef::new("en0", NetworkDevice::eth()).v6())?;

            let mut count = 0;
            let mut sock = RawIpSocket::new_v6()?;
            sock.bind_proto(42)?;
            loop {
                tokio::select! {
                    frame = sock.recv() => {
                        let (_, pkt) = frame.unwrap();
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

    tx.connect_with(
        rx,
        Some(DatarateChannel::new(DatarateChannelMetrics {
            bitrate: 1000_000,
            latency: Duration::from_millis(20),
            jitter: Duration::ZERO,
            drop_behaviour: ChannelDropBehaviour::Queue(None),
        })),
    );

    let rt = Builder::seeded(123).build(sim.freeze());
    let result = rt.run().map(|_| ());

    assert!(DONE.load(std::sync::atomic::Ordering::SeqCst));
    result
}

#[test]
#[serial]
fn interface_will_use_idle_channel_fcfs() -> Result<(), RuntimeError> {
    static DONE: AtomicBool = AtomicBool::new(false);

    let mut sim = Sim::new(()).with_stack(inet::init);
    sim.node(
        "sender",
        AsyncHandler::failable::<_, _, std::io::Error>(|_| async move {
            set_node_cfg(HostConfiguration {
                dup_addr_detect_for_link_local: false,
                dup_addr_detect_transmits: 0,
            })?;
            ioctx().add_interface(InterfaceDef::new("en0", NetworkDevice::eth()).v6())?;

            // Sleep to prevent MLD messags from blocking the sender
            des::time::sleep(Duration::from_secs(1)).await;

            let sock = RawIpSocket::new_v6()?;
            sock.try_send(IpPacket::V6(Ipv6Packet {
                traffic_class: 0,
                flow_label: 0,
                proto: 42,
                hop_limit: 32,
                extension_headers: Vec::new(),
                src: Ipv6Addr::UNSPECIFIED,
                dst: Ipv6Addr::MULTICAST_ALL_NODES,
                content: Bytes::new(),
            }))?;

            for i in 0..32 {
                send(Message::default().with_id(32 + i), "port").unwrap();
            }

            Ok(())
        }),
    );

    sim.node(
        "receiver",
        AsyncHandler::failable::<_, _, std::io::Error>(|mut rx| async move {
            set_node_cfg(HostConfiguration {
                dup_addr_detect_for_link_local: false,
                dup_addr_detect_transmits: 0,
            })?;
            ioctx().add_interface(InterfaceDef::new("en0", NetworkDevice::eth()).v6())?;

            let mut count = 0;
            let mut sock = RawIpSocket::new_v6()?;
            sock.bind_proto(42)?;
            loop {
                tokio::select! {
                    frame = sock.recv() => {
                        let (_, pkt) = frame.unwrap();
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

    so.connect_with(
        co,
        Some(DatarateChannel::new(DatarateChannelMetrics {
            bitrate: 1000_000,
            latency: Duration::from_millis(20),
            jitter: Duration::ZERO,
            drop_behaviour: ChannelDropBehaviour::Queue(None),
        })),
    );

    let rt = Builder::seeded(123).build(sim.freeze());
    let result = rt.run().map(|_| ());

    assert!(DONE.load(std::sync::atomic::Ordering::SeqCst));
    result
}

#[test]
#[serial]
fn cannot_add_interface_with_same_name() -> Result<(), RuntimeError> {
    let mut sim = Sim::new(()).with_stack(inet::init);
    sim.node(
        "sender",
        AsyncHandler::failable::<_, _, std::io::Error>(|_| async move {
            ioctx().add_interface(InterfaceDef::new("en0", NetworkDevice::eth()).v6())?;
            let err = ioctx()
                .add_interface(InterfaceDef::new("en0", NetworkDevice::eth()).v6())
                .expect_err("must have failed");
            assert_eq!(err.kind(), ErrorKind::Other);
            assert_eq!(err.to_string(), "cannot duplicate interface with name en0");

            Ok(())
        })
        .require_join(),
    );

    let a = sim.gate("sender", "port");
    let b = sim.gate("sender", "dummy");
    a.connect(b);

    let rt = Builder::seeded(123).build(sim.freeze());
    rt.run().map(|_| ())
}

#[test]
#[serial]
fn eth_device_on_nodelay_link() -> Result<(), RuntimeError> {
    let mut sim = Sim::new(()).with_stack(inet::init);
    sim.node(
        "sender",
        AsyncHandler::failable::<_, _, std::io::Error>(|_| async move {
            ioctx()
                .add_interface(InterfaceDef::new("en0", NetworkDevice::eth()).v6())?
                .wait_for_link_local()
                .await;

            let v6 = RawIpSocket::new_v6()?;
            v6.try_send(IpPacket::V6(Ipv6Packet {
                traffic_class: 0,
                flow_label: 0,
                proto: PROTO_UDP,
                src: "::".parse().unwrap(),
                dst: "fe80::2".parse().unwrap(),
                hop_limit: 64,
                extension_headers: Vec::new(),
                content: Bytes::from_static(b"12312312312"),
            }))?;

            Ok(())
        })
        .require_join(),
    );

    let a = sim.gate("sender", "port");
    let b = sim.gate("sender", "dummy");
    a.connect(b);

    let rt = Builder::seeded(123).build(sim.freeze());
    rt.run().map(|_| ())
}

#[test]
#[serial]
fn eth_device_from_selection() -> Result<(), RuntimeError> {
    let mut sim = Sim::new(()).with_stack(inet::init);
    sim.node(
        "sender",
        AsyncHandler::failable::<_, _, std::io::Error>(|_| async move {
            ioctx().add_interface(
                InterfaceDef::new("en0", NetworkDevice::eth_select(|p| p.name == "tom")).v6(),
            )?;

            ioctx().add_interface(
                InterfaceDef::new("en1", NetworkDevice::bidirectional("tim")).v6(),
            )?;

            Ok(())
        })
        .require_join(),
    );

    let a = sim.gate("sender", "tim");
    let b = sim.gate("sender", "tom");
    a.connect(b);

    let rt = Builder::seeded(123).build(sim.freeze());
    rt.run().map(|_| ())
}

#[test]
#[serial]
fn interface_handle_add_addr() -> Result<(), RuntimeError> {
    let mut sim = Sim::new(()).with_stack(inet::init);
    sim.node(
        "sender",
        AsyncHandler::failable::<_, _, std::io::Error>(|_| async move {
            let handle =
                ioctx().add_interface(InterfaceDef::new("en0", NetworkDevice::eth()).v6())?;

            assert_eq!(handle.id(), IfId::new("en0"));
            handle.add_addr("192.168.2.101".parse().unwrap())?;
            handle.add_addr("2003:a:b::1".parse().unwrap())?;

            assert_eq!(
                handle.status().addrs.v4.unicast[0].addr,
                "192.168.2.101".parse::<Ipv4Addr>().unwrap()
            );

            // no v6 addr is ready yet;
            assert_eq!(handle.status().addrs.v6.unicast.len(), 0);
            sleep(Duration::from_secs(5)).await; // wait for ready
            assert_eq!(handle.status().addrs.v6.unicast.len(), 2);

            Ok(())
        }),
    );

    let a = sim.gate("sender", "port");
    let b = sim.gate("sender", "dummy");

    a.connect(b);

    let rt = Builder::seeded(123).build(sim.freeze());
    rt.run().map(|_| ())
}
