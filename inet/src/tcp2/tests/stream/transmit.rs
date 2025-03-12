use std::{net::Ipv4Addr, sync::Arc, time::Duration};

use des::{
    net::{AsyncFn, HandlerFn, Sim},
    prelude::{send, Channel, ChannelDropBehaviour, ChannelMetrics},
    runtime::{random, Builder},
};
use rand::{rng, RngCore};
use serial_test::serial;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::{
    interface::{add_interface, InterfaceDef, NetworkDevice},
    tcp2::{set_config, Config, TcpListener, TcpStream},
};

#[serial]
#[test]
fn large_stream() {
    // des::tracing::init();

    let mut sim = Sim::new(()).with_stack(crate::init);
    let mut bytes = vec![0; 8_000_000]; // 8MB;
    rng().fill_bytes(&mut bytes);

    let bytes = Arc::new(bytes);
    let bytes2 = bytes.clone();
    sim.node(
        "alice",
        AsyncFn::io(move |_| {
            let bytes = bytes.clone();
            async move {
                add_interface(
                    InterfaceDef::new("en0", NetworkDevice::eth())
                        .ip(Ipv4Addr::new(100, 0, 0, 42).into()),
                )?;

                set_config(Config {
                    // enable_congestion_control: true,
                    send_buffer_cap: (u16::MAX / 2) as usize,
                    recv_buffer_cap: (u16::MAX / 2) as usize,
                    ..Default::default()
                });

                let mut stream = TcpStream::connect("100.0.0.69:8000").await?;
                stream.write_all(&bytes).await?;

                Ok(())
            }
        })
        .require_join(),
    );

    sim.node(
        "bob",
        AsyncFn::io(move |_| {
            let bytes = bytes2.clone();
            async move {
                add_interface(
                    InterfaceDef::new("en0", NetworkDevice::eth())
                        .ip(Ipv4Addr::new(100, 0, 0, 69).into()),
                )?;

                set_config(Config {
                    // enable_congestion_control: true,
                    send_buffer_cap: (u16::MAX / 2) as usize,
                    recv_buffer_cap: (u16::MAX / 2) as usize,
                    ..Default::default()
                });

                let li = TcpListener::bind("0.0.0.0:8000").await?;
                let (mut sock, _) = li.accept().await?;

                let mut rem = &bytes[..];
                while !rem.is_empty() {
                    let mut buf = [0; 1500];
                    let n = sock.read(&mut buf).await?;

                    assert!(n > 0);
                    assert_eq!(buf[..n], rem[..n]);
                    rem = &rem[n..];
                }

                Ok(())
            }
        }),
    );

    let a = sim.gate("alice", "port");
    let b = sim.gate("bob", "port");
    a.connect(
        b,
        Some(Channel::new(ChannelMetrics::new(
            8_000_000, // 1MB
            Duration::from_millis(30),
            Duration::ZERO,
            ChannelDropBehaviour::Queue(None),
        ))),
    );

    let _ = Builder::seeded(123)
        .max_time(1000.0.into())
        .build(sim)
        .run();

    // Event Count
    // 8MB - max 536 bytes per packet
    // -> 14925 packets one way
    // -> 29850 + 7 packets two way
    // -> 3 Events per Packet
    //   - Arriving on Channel (ChannelUnbusyNotif)
    //   - Existing Channel (MessageExitingConnection)
    //   - HandleMessageEvent
    // -> 89571 events for packet management
    // -> + various timers per socket
    //
    // -> actual = 120964
    // -> 31393 timer packets
}

#[serial]
#[test]
fn lossful_stream() {
    // des::tracing::init();

    let mut sim = Sim::new(()).with_stack(crate::init);
    let mut bytes = vec![0; 100_000]; // 8MB;
    rng().fill_bytes(&mut bytes);

    let bytes = Arc::new(bytes);
    let bytes2 = bytes.clone();
    sim.node(
        "alice",
        AsyncFn::io(move |_| {
            let bytes = bytes.clone();
            async move {
                add_interface(
                    InterfaceDef::new("en0", NetworkDevice::eth())
                        .ip(Ipv4Addr::new(100, 0, 0, 42).into()),
                )?;

                set_config(Config {
                    enable_congestion_control: true,
                    send_buffer_cap: (u16::MAX / 2) as usize,
                    recv_buffer_cap: (u16::MAX / 2) as usize,
                    ..Default::default()
                });

                let mut stream = TcpStream::connect("100.0.0.69:8000").await?;
                stream.write_all(&bytes).await?;

                Ok(())
            }
        })
        .require_join(),
    );

    sim.node(
        "bob",
        AsyncFn::io(move |_| {
            let bytes = bytes2.clone();
            async move {
                add_interface(
                    InterfaceDef::new("en0", NetworkDevice::eth())
                        .ip(Ipv4Addr::new(100, 0, 0, 69).into()),
                )?;

                set_config(Config {
                    enable_congestion_control: true,
                    send_buffer_cap: (u16::MAX / 2) as usize,
                    recv_buffer_cap: (u16::MAX / 2) as usize,
                    ..Default::default()
                });

                let li = TcpListener::bind("0.0.0.0:8000").await?;
                let (mut sock, _) = li.accept().await?;

                let mut rem = &bytes[..];
                while !rem.is_empty() {
                    let mut buf = [0; 1500];
                    let n = sock.read(&mut buf).await?;
                    tracing::info!("<RECV {n} bytes | remaining {}>", rem.len());

                    assert!(n > 0);
                    assert_eq!(buf[..n], rem[..n]);
                    rem = &rem[n..];
                }

                Ok(())
            }
        }),
    );

    sim.node(
        "link",
        HandlerFn::new(
            |msg| match msg.header().last_gate.as_ref().unwrap().name() {
                "port-alice" if random::<u8>() > 32 => send(msg, "port-bob"),
                "port-bob" if random::<u8>() > 32 => send(msg, "port-alice"),
                _ => tracing::error!(
                    kind = msg.header().kind,
                    "dropping packet from {:?}",
                    msg.header().last_gate
                ),
            },
        ),
    );

    let a = sim.gate("alice", "port");
    let a_con = sim.gate("link", "port-alice");
    let b = sim.gate("bob", "port");
    let b_con = sim.gate("link", "port-bob");
    a.connect(
        a_con,
        Some(Channel::new(ChannelMetrics::new(
            8_000_000, // 1MB
            Duration::from_millis(30),
            Duration::ZERO,
            ChannelDropBehaviour::Queue(None),
        ))),
    );
    b.connect(
        b_con,
        Some(Channel::new(ChannelMetrics::new(
            8_000_000, // 1MB
            Duration::from_millis(30),
            Duration::ZERO,
            ChannelDropBehaviour::Queue(None),
        ))),
    );

    let _ = Builder::seeded(123).max_time(100.0.into()).build(sim).run();

    // DROP #1: ArpResponse
    // Drop #2: SYN
}
