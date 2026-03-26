use std::{io::ErrorKind, net::SocketAddr};

use serial_test::serial;
use tokio::io::AsyncWriteExt;

use crate::{
    ioctx,
    socket::AsRawFd,
    tcp::{self, Config, TcpListener, TcpStream},
    utils::SimpleSim,
};

#[test]
#[serial]
fn bind_fails_after_all_addrs() -> Result<(), des::net::Failure> {
    let mut sim = SimpleSim::default();
    sim.node("192.168.2.101", || async move {
        let binding = TcpListener::bind(("2003:a:1::1", 80))
            .await
            .expect_err("must fail since there is no binding addr");

        assert_eq!(binding.kind(), ErrorKind::AddrNotAvailable);
        assert_eq!(
            binding.to_string(),
            "address not available - specific bind failed"
        );
        Ok(())
    });

    sim.run()
}

#[test]
#[serial]
fn bind_fails_no_addrs() -> Result<(), des::net::Failure> {
    let mut sim = SimpleSim::default();
    sim.node_require_join("192.168.2.101", || async move {
        let binding = TcpListener::bind::<&[SocketAddr]>(&[])
            .await
            .expect_err("must fail since there is no binding addr");

        assert_eq!(binding.to_string(), "could not resolve to any address");
        Ok(())
    });

    sim.run()
}

#[test]
#[serial]
fn accept_incoming() -> Result<(), des::net::Failure> {
    let mut sim = SimpleSim::default();
    sim.node_require_join("192.168.2.101", || async move {
        let binding = TcpListener::bind("0.0.0.0:80").await?;
        let _accepted = binding.accept().await?;

        Ok(())
    });
    sim.node("192.168.2.102", || async move {
        TcpStream::connect("192.168.2.101:80")
            .await?
            .write_all(&[1, 2, 3, 4])
            .await?;
        Ok(())
    });

    sim.run()
}

#[test]
#[serial]
fn accepted_socket_not_unspecified_v4() -> Result<(), des::net::Failure> {
    let mut sim = SimpleSim::default();
    sim.node_require_join("192.168.2.101", || async move {
        let binding = TcpListener::bind("0.0.0.0:80").await?;
        let (accepted, _) = binding.accept().await?;
        assert_eq!(
            ioctx().bsd_socket_info(accepted.as_raw_fd())?.addr,
            "192.168.2.101:80".parse().unwrap()
        );
        Ok(())
    });
    sim.node("192.168.2.102", || async move {
        TcpStream::connect("192.168.2.101:80")
            .await?
            .write_all(&[1, 2, 3, 4])
            .await?;
        Ok(())
    });

    sim.run()
}

#[test]
#[serial]
fn accepted_socket_not_unspecified_v6() -> Result<(), des::net::Failure> {
    let mut sim = SimpleSim::default();
    sim.node_require_join("fe80::1", || async move {
        let binding = TcpListener::bind("[::]:80").await?;
        let (accepted, _) = binding.accept().await?;
        assert_eq!(
            ioctx().bsd_socket_info(accepted.as_raw_fd())?.addr,
            "[fe80::1]:80".parse().unwrap()
        );
        Ok(())
    });
    sim.node("fe80::2", || async move {
        TcpStream::connect("[fe80::1]:80")
            .await?
            .write_all(&[1, 2, 3, 4])
            .await?;
        Ok(())
    });

    sim.run()
}

#[test]
#[serial]
fn socketopt_ttl() -> Result<(), des::net::Failure> {
    let mut sim = SimpleSim::default();
    sim.node_require_join("192.168.2.101", || async move {
        let binding = TcpListener::bind("0.0.0.0:0").await?;
        assert_eq!(binding.ttl()?, 64);

        tcp::set_config(Config {
            ttl: 42,
            ..Default::default()
        });

        let binding = TcpListener::bind("0.0.0.0:0").await?;
        assert_eq!(binding.ttl()?, 42);

        binding.set_ttl(32)?;
        assert_eq!(binding.ttl()?, 32);

        Ok(())
    });

    sim.run()
}
