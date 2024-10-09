use std::{io::ErrorKind, net::Ipv4Addr, time::Duration};

use des::{
    net::{AsyncFn, Sim},
    prelude::{Channel, ChannelDropBehaviour, ChannelMetrics},
    runtime::Builder,
};
use serial_test::serial;

use crate::{
    interface::{add_interface, Interface, NetworkDevice},
    tcp2::{set_config, Config, TcpStream},
};

#[serial]
#[test]
fn connect_without_interface() {
    let mut sim = Sim::new(()).with_stack(crate::init);
    sim.node(
        "alice",
        AsyncFn::io(|_| async move {
            let stream = TcpStream::connect("69.0.0.69:8000").await;
            let err = stream.unwrap_err();
            assert_eq!(err.kind(), ErrorKind::AddrNotAvailable);
            assert_eq!(err.to_string(), "Address not available");
            Ok(())
        })
        .require_join(),
    );

    let _ = Builder::seeded(123)
        .max_time(100.0.into())
        .max_itr(100)
        .build(sim)
        .run();
}

#[serial]
#[test]
fn connect_ip_version_missmatch() {
    let mut sim = Sim::new(()).with_stack(crate::init);
    sim.node(
        "alice",
        AsyncFn::io(|_| async move {
            add_interface(Interface::ethv4(
                NetworkDevice::eth(),
                Ipv4Addr::new(42, 0, 0, 42),
            ))?;

            let stream = TcpStream::connect("2000:132:32::0:8000").await;
            let err = stream.unwrap_err();
            assert_eq!(err.kind(), ErrorKind::ConnectionRefused);
            assert_eq!(err.to_string(), "host unreachable - no valid src addr");
            Ok(())
        })
        .require_join(),
    );

    sim.node(
        "bob",
        AsyncFn::new(|_| async move {
            // NOP
        }),
    );

    let a = sim.gate("alice", "port");
    let b = sim.gate("bob", "port");
    a.connect(
        b,
        Some(Channel::new(ChannelMetrics::new(
            80000,
            Duration::from_millis(200),
            Duration::ZERO,
            ChannelDropBehaviour::Queue(None),
        ))),
    );

    let _ = Builder::seeded(123)
        .max_time(100.0.into())
        .max_itr(100)
        .build(sim)
        .run();
}

#[serial]
#[test]
fn connect_without_ipv4_gateway() {
    let mut sim = Sim::new(()).with_stack(crate::init);
    sim.node(
        "alice",
        AsyncFn::io(|_| async move {
            add_interface(Interface::ethv4(
                NetworkDevice::eth(),
                Ipv4Addr::new(42, 0, 0, 42),
            ))?;

            let stream = TcpStream::connect("69.0.0.69:8000").await;
            let err = stream.unwrap_err();
            assert_eq!(err.kind(), ErrorKind::ConnectionRefused);
            assert_eq!(err.to_string(), "no gateway network reachable");
            Ok(())
        })
        .require_join(),
    );

    sim.node(
        "bob",
        AsyncFn::new(|_| async move {
            // NOP
        }),
    );

    let a = sim.gate("alice", "port");
    let b = sim.gate("bob", "port");
    a.connect(
        b,
        Some(Channel::new(ChannelMetrics::new(
            80000,
            Duration::from_millis(200),
            Duration::ZERO,
            ChannelDropBehaviour::Queue(None),
        ))),
    );

    let _ = Builder::seeded(123)
        .max_time(100.0.into())
        .max_itr(100)
        .build(sim)
        .run();
}

#[serial]
#[test]
fn connect_to_non_listener_peer() {
    let mut sim = Sim::new(()).with_stack(crate::init);
    sim.node(
        "alice",
        AsyncFn::io(|_| async move {
            add_interface(Interface::ethv4(
                NetworkDevice::eth(),
                Ipv4Addr::new(100, 0, 0, 42),
            ))?;

            let stream = TcpStream::connect("100.0.0.69:8000").await;
            let err = stream.unwrap_err();
            assert_eq!(err.kind(), ErrorKind::ConnectionRefused);
            assert_eq!(err.to_string(), "connection refused by peer");
            Ok(())
        })
        .require_join(),
    );

    sim.node(
        "bob",
        AsyncFn::io(|_| async move {
            add_interface(Interface::ethv4(
                NetworkDevice::eth(),
                Ipv4Addr::new(100, 0, 0, 69),
            ))?;
            Ok(())
        }),
    );

    let a = sim.gate("alice", "port");
    let b = sim.gate("bob", "port");
    a.connect(
        b,
        Some(Channel::new(ChannelMetrics::new(
            80000,
            Duration::from_millis(200),
            Duration::ZERO,
            ChannelDropBehaviour::Queue(None),
        ))),
    );

    let _ = Builder::seeded(123)
        .max_time(100.0.into())
        .max_itr(100)
        .build(sim)
        .run();
}

#[serial]
#[test]
fn connect_syn_timeout_no_rst() {
    let mut sim = Sim::new(()).with_stack(crate::init);
    sim.node(
        "alice",
        AsyncFn::io(|_| async move {
            add_interface(Interface::ethv4(
                NetworkDevice::eth(),
                Ipv4Addr::new(100, 0, 0, 42),
            ))?;

            let stream = TcpStream::connect("100.0.0.69:8000").await;
            let err = stream.unwrap_err();
            assert_eq!(err.kind(), ErrorKind::ConnectionRefused);
            assert_eq!(
                err.to_string(),
                "host unreachable: syn resend count exceeded"
            );
            Ok(())
        })
        .require_join(),
    );

    sim.node(
        "bob",
        AsyncFn::io(|_| async move {
            add_interface(Interface::ethv4(
                NetworkDevice::eth(),
                Ipv4Addr::new(100, 0, 0, 69),
            ))?;
            set_config(Config {
                rst_for_syn: false,
                ..Default::default()
            });
            Ok(())
        }),
    );

    let a = sim.gate("alice", "port");
    let b = sim.gate("bob", "port");
    a.connect(
        b,
        Some(Channel::new(ChannelMetrics::new(
            80000,
            Duration::from_millis(200),
            Duration::ZERO,
            ChannelDropBehaviour::Queue(None),
        ))),
    );

    let _ = Builder::seeded(123)
        .max_time(100.0.into())
        .max_itr(100)
        .build(sim)
        .run();
}
