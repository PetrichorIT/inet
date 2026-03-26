use std::{
    io::ErrorKind,
    net::{Ipv4Addr, SocketAddr},
    time::Duration,
};

use des::{
    net::{Sim, handlers::AsyncHandler},
    runtime::Builder,
    time::SimTime,
};
use serial_test::serial;

use crate::{
    interface::{InterfaceDef, NetworkDevice},
    ioctx,
    socket::AsRawFd,
    tcp::{Config, TcpListener, TcpStream, set_config},
    utils::SimpleSim,
};

use super::run_default_sim;

#[serial]
#[test]
fn connect_without_interface() {
    let mut sim = Sim::new(()).with_stack(crate::init);
    sim.node(
        "alice",
        AsyncHandler::io(|_| async move {
            let stream = TcpStream::connect("69.0.0.69:8000").await;
            let err = stream.unwrap_err();
            assert_eq!(err.kind(), ErrorKind::AddrNotAvailable);
            assert_eq!(err.to_string(), "address not available");
            Ok(())
        })
        .require_join(),
    );

    let _ = Builder::seeded(123)
        .max_time(100.0.into())
        .max_itr(100)
        .build(sim.freeze())
        .run();
}

#[serial]
#[test]
fn connect_ip_version_missmatch() {
    let mut sim = Sim::new(()).with_stack(crate::init);
    sim.node(
        "alice",
        AsyncHandler::io(|_| async move {
            ioctx().add_interface(
                InterfaceDef::new("en0", NetworkDevice::eth())
                    .ip(Ipv4Addr::new(42, 0, 0, 42).into()),
            )?;

            let stream = TcpStream::connect("2000:132:32::0:8000").await;
            let err = stream.unwrap_err();

            assert_eq!(err.kind(), ErrorKind::ConnectionRefused);
            assert_eq!(err.to_string(), "host unreachable - no valid src addr");
            assert_eq!(SimTime::now(), SimTime::ZERO);

            Ok(())
        })
        .require_join(),
    );

    sim.node(
        "bob",
        AsyncHandler::new(|_| async move {
            // NOP
        }),
    );

    run_default_sim(sim);
}

#[serial]
#[test]
fn connect_without_ipv4_gateway() {
    let mut sim = Sim::new(()).with_stack(crate::init);
    sim.node(
        "alice",
        AsyncHandler::io(|_| async move {
            ioctx().add_interface(
                InterfaceDef::new("en0", NetworkDevice::eth())
                    .ip(Ipv4Addr::new(42, 0, 0, 42).into()),
            )?;

            let stream = TcpStream::connect("69.0.0.69:8000").await;
            let err = stream.unwrap_err();

            assert_eq!(err.kind(), ErrorKind::ConnectionRefused);
            assert_eq!(err.to_string(), "no gateway network reachable");
            assert_eq!(SimTime::now(), SimTime::ZERO);

            Ok(())
        })
        .require_join(),
    );

    sim.node(
        "bob",
        AsyncHandler::new(|_| async move {
            // NOP
        }),
    );

    run_default_sim(sim);
}

#[serial]
#[test]
fn connect_to_non_listener_peer() {
    let mut sim = Sim::new(()).with_stack(crate::init);
    sim.node(
        "alice",
        AsyncHandler::io(|_| async move {
            ioctx().add_interface(
                InterfaceDef::new("en0", NetworkDevice::eth())
                    .ip(Ipv4Addr::new(100, 0, 0, 42).into()),
            )?;

            let stream = TcpStream::connect("100.0.0.69:8000").await;
            let err = stream.unwrap_err();
            assert_eq!(err.kind(), ErrorKind::ConnectionReset);
            assert_eq!(err.to_string(), "connection reset: RST+ACK in SYN_SNT");
            Ok(())
        })
        .require_join(),
    );

    sim.node(
        "bob",
        AsyncHandler::io(|_| async move {
            ioctx().add_interface(
                InterfaceDef::new("en0", NetworkDevice::eth())
                    .ip(Ipv4Addr::new(100, 0, 0, 69).into()),
            )?;
            Ok(())
        }),
    );

    run_default_sim(sim);
}

#[serial]
#[test]
fn connect_syn_timeout_no_rst() {
    let mut sim = Sim::new(()).with_stack(crate::init);
    sim.node(
        "alice",
        AsyncHandler::io(|_| async move {
            ioctx().add_interface(
                InterfaceDef::new("en0", NetworkDevice::eth())
                    .ip(Ipv4Addr::new(100, 0, 0, 42).into()),
            )?;

            let stream = TcpStream::connect("100.0.0.69:8000").await;
            tracing::info!("CONNECT OR ERR");
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
        AsyncHandler::io(|_| async move {
            ioctx().add_interface(
                InterfaceDef::new("en0", NetworkDevice::eth())
                    .ip(Ipv4Addr::new(100, 0, 0, 69).into()),
            )?;
            set_config(Config {
                rst_for_syn: false,
                ..Default::default()
            });
            Ok(())
        }),
    );

    run_default_sim(sim);
}

#[serial]
#[test]
fn connect_fails_no_addr() -> Result<(), des::net::Failure> {
    let mut sim = SimpleSim::default();
    sim.node_require_join("192.168.2.101", || async move {
        let error = TcpStream::connect::<&[SocketAddr]>(&[])
            .await
            .expect_err("must fail");
        assert_eq!(error.to_string(), "could not resolve to any address");
        Ok(())
    });

    sim.run()
}

#[serial]
#[test]
fn connect_fails_after_all_addr() -> Result<(), des::net::Failure> {
    let mut sim = SimpleSim::default();
    sim.node_require_join("192.168.2.101", || async move {
        let error = TcpStream::connect(("2003:a:1::3123", 0))
            .await
            .expect_err("must fail");
        assert_eq!(error.to_string(), "address not available");
        Ok(())
    });

    sim.run()
}

#[serial]
#[test]
fn connect_success() {
    let mut sim = Sim::new(()).with_stack(crate::init);
    sim.node(
        "alice",
        AsyncHandler::io(|_| async move {
            ioctx().add_interface(
                InterfaceDef::new("en0", NetworkDevice::eth())
                    .ip(Ipv4Addr::new(100, 0, 0, 42).into()),
            )?;

            let stream = TcpStream::connect("100.0.0.69:8000").await?;
            assert_eq!(stream.local_addr()?, "100.0.0.42:1024".parse().unwrap());
            tracing::info!("CONNECT");
            Ok(())
        })
        .require_join(),
    );

    sim.node(
        "bob",
        AsyncHandler::io(|_| async move {
            ioctx().add_interface(
                InterfaceDef::new("en0", NetworkDevice::eth())
                    .ip(Ipv4Addr::new(100, 0, 0, 69).into()),
            )?;
            let list = TcpListener::bind("0.0.0.0:8000").await?;
            let (_sock, _from) = list.accept().await?;
            Ok(())
        })
        .require_join(),
    );

    run_default_sim(sim);
}

#[serial]
#[test]
fn connect_success_without_accept() {
    let mut sim = Sim::new(()).with_stack(crate::init);
    sim.node(
        "alice",
        AsyncHandler::io(|_| async move {
            ioctx().add_interface(
                InterfaceDef::new("en0", NetworkDevice::eth())
                    .ip(Ipv4Addr::new(100, 0, 0, 42).into()),
            )?;

            let _stream = TcpStream::connect("100.0.0.69:8000").await?;
            tracing::info!("CONNECT");
            Ok(())
        })
        .require_join(),
    );

    sim.node(
        "bob",
        AsyncHandler::io(|_| async move {
            ioctx().add_interface(
                InterfaceDef::new("en0", NetworkDevice::eth())
                    .ip(Ipv4Addr::new(100, 0, 0, 69).into()),
            )?;
            let list = TcpListener::bind("0.0.0.0:8000").await?;
            des::time::sleep(Duration::from_secs(10)).await;
            drop(list);
            Ok(())
        })
        .require_join(),
    );

    run_default_sim(sim);
}

#[serial]
#[test]
fn connect_introduces_local_specified_addr_v4() -> Result<(), des::net::Failure> {
    let mut sim = SimpleSim::new(crate::init);
    sim.node_require_join("100.0.0.42", || async move {
        let stream = TcpStream::connect("100.0.0.69:8000").await?;
        assert_eq!(
            ioctx().bsd_socket_info(stream.as_raw_fd())?.addr,
            "100.0.0.42:1024".parse().unwrap()
        );
        Ok(())
    });
    sim.node_require_join("100.0.0.69", || async move {
        let list = TcpListener::bind("0.0.0.0:8000").await?;
        des::time::sleep(Duration::from_secs(10)).await;
        drop(list);
        Ok(())
    });

    sim.run()
}

#[serial]
#[test]
fn connect_introduces_local_specified_addr_v6() -> Result<(), des::net::Failure> {
    let mut sim = SimpleSim::new(crate::init);
    sim.node_require_join("fe80::1", || async move {
        let stream = TcpStream::connect("[fe80::2]:8000").await?;
        assert_eq!(
            ioctx().bsd_socket_info(stream.as_raw_fd())?.addr,
            "[fe80::1]:1024".parse().unwrap()
        );
        Ok(())
    });
    sim.node_require_join("fe80::2", || async move {
        let list = TcpListener::bind("[::]:8000").await?;
        des::time::sleep(Duration::from_secs(10)).await;
        drop(list);
        Ok(())
    });

    sim.run()
}
