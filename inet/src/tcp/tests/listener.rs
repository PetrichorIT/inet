use std::{io::ErrorKind, net::SocketAddr};

use des::runtime::RuntimeError;
use serial_test::serial;
use tokio::io::AsyncWriteExt;

use crate::{
    tcp::{self, Config, TcpListener, TcpStream},
    test_util::SimpleSim,
};

#[test]
#[serial]
fn bind_fails_after_all_addrs() -> Result<(), RuntimeError> {
    let mut sim = SimpleSim::default();
    sim.node("192.168.2.101", || async move {
        let binding = TcpListener::bind(("2003:a:1::1", 80))
            .await
            .expect_err("must fail since there is no binding addr");

        assert_eq!(binding.kind(), ErrorKind::AddrNotAvailable);
        assert_eq!(binding.to_string(), "Address not available");
        Ok(())
    });

    sim.run()
}

#[test]
#[serial]
fn bind_fails_no_addrs() -> Result<(), RuntimeError> {
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
fn accept_incoming() -> Result<(), RuntimeError> {
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
fn socketopt_ttl() -> Result<(), RuntimeError> {
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
