use std::{net::Ipv4Addr, sync::Arc, time::Duration};

use des::{
    Sim,
    gate::IntoGate,
    prelude::{ChannelDropBehaviour, DatarateChannel, DatarateChannelMetrics, send},
    runtime::{
        handlers::{AsyncHandler, HandlerFn},
        random,
    },
    time::SimTime,
};
use rand::{RngCore, rng};
use serial_test::serial;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::{
    interface::{InterfaceDef, NetworkDevice},
    ioctx,
    tcp::{
        Config, TcpListener, TcpStream, set_config,
        tests::stream::consume_any_data_echo_if_possible,
    },
    utils::SimpleSim,
};

#[serial]
#[test]
fn peeking_stream() -> Result<(), des::Failure> {
    let mut sim = SimpleSim::default();
    sim.node_require_join("192.168.2.101", || async move {
        let (mut accepted, _) = TcpListener::bind("0.0.0.0:80").await?.accept().await?;
        let mut buf = [0; 1024];
        loop {
            let n = accepted.peek(&mut buf).await?;
            if n == 1024 {
                accepted.read(&mut buf).await?;
                break;
            }
        }

        Ok(())
    });

    sim.node_require_join("192.168.2.102", || async move {
        TcpStream::connect("192.168.2.101:80")
            .await?
            .write_all(&[1; 1024])
            .await?;
        Ok(())
    });

    sim.run()
}

#[test]
#[serial]
fn interest_based_writing() -> Result<(), des::Failure> {
    let mut sim = SimpleSim::default();
    sim.node("192.168.2.101", || async move {
        let (accepted, _) = TcpListener::bind("0.0.0.0:80").await?.accept().await?;
        consume_any_data_echo_if_possible(accepted).await
    });

    sim.node_require_join("192.168.2.102", || async move {
        let stream = TcpStream::connect("192.168.2.101:80").await?;
        let mut acc = 0;
        while acc < 100_000 {
            stream.writable().await?;
            acc += stream.try_write(&[1; 1024])?;
        }

        assert!(SimTime::now().as_secs_f64() > 1.2);
        Ok(())
    });

    sim.run()
}

#[serial]
#[test]
fn large_stream() {
    let mut sim = Sim::new(()).with_stack(crate::init);
    let mut bytes = vec![0; 8_000_000]; // 8MB;
    rng().fill_bytes(&mut bytes);

    let bytes = Arc::new(bytes);
    let bytes2 = bytes.clone();
    sim.node(
        "alice",
        AsyncHandler::io(move |_| {
            let bytes = bytes.clone();
            async move {
                ioctx().add_interface(
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
        AsyncHandler::io(move |_| {
            let bytes = bytes2.clone();
            async move {
                ioctx().add_interface(
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
    a.connect_with(
        b,
        Some(DatarateChannel::new(DatarateChannelMetrics::new(
            8_000_000, // 1MB
            Duration::from_millis(30),
            Duration::ZERO,
            ChannelDropBehaviour::Queue(None),
        ))),
    );

    let _ = sim.seeded(123).max_time(1000.0.into()).build().run();

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
        AsyncHandler::io(move |_| {
            let bytes = bytes.clone();
            async move {
                ioctx().add_interface(
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
        AsyncHandler::io(move |_| {
            let bytes = bytes2.clone();
            async move {
                ioctx().add_interface(
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
        HandlerFn::new(|msg| match msg.header.last_gate.as_ref().unwrap().name() {
            "port-alice" if random::<u8>() > 32 => {
                let _ = send(msg, "port-bob");
            }
            "port-bob" if random::<u8>() > 32 => {
                let _ = send(msg, "port-alice");
            }
            _ => tracing::error!(
                kind = msg.header.kind,
                "dropping packet from {:?}",
                msg.header.last_gate
            ),
        }),
    );

    let a = sim.gate("alice", "port");
    let a_con = sim.gate("link", "port-alice");
    let b = sim.gate("bob", "port");
    let b_con = sim.gate("link", "port-bob");
    a.connect_with(
        a_con,
        Some(DatarateChannel::new(DatarateChannelMetrics::new(
            8_000_000, // 1MB
            Duration::from_millis(30),
            Duration::ZERO,
            ChannelDropBehaviour::Queue(None),
        ))),
    );
    b.connect_with(
        b_con,
        Some(DatarateChannel::new(DatarateChannelMetrics::new(
            8_000_000, // 1MB
            Duration::from_millis(30),
            Duration::ZERO,
            ChannelDropBehaviour::Queue(None),
        ))),
    );

    let _ = sim.seeded(123).max_time(100.0.into()).build().run();

    // DROP #1: ArpResponse
    // Drop #2: SYN
}
