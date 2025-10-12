use std::time::Duration;

use des::runtime::RuntimeError;
use serial_test::serial;

use crate::{
    tcp::{self, Config, TcpListener, TcpStream},
    test_util::SimpleSim,
};

#[test]
#[serial]
fn linger() -> Result<(), RuntimeError> {
    let mut sim = SimpleSim::default();
    sim.node("192.168.2.101", || async move {
        let l = TcpListener::bind("0.0.0.0:80").await?;
        loop {
            let (_accepted, _) = l.accept().await?;
        }
    });

    sim.node("192.168.2.102", || async move {
        let stream = TcpStream::connect("192.168.2.101:80").await?;
        assert_eq!(stream.linger()?, None);

        tcp::set_config(Config {
            linger: Some(Duration::from_secs(1)),
            ..Default::default()
        });
        let stream = TcpStream::connect("192.168.2.101:80").await?;
        assert_eq!(stream.linger()?, Some(Duration::from_secs(1)));

        stream.set_linger(Some(Duration::from_secs(2)))?;
        assert_eq!(stream.linger()?, Some(Duration::from_secs(2)));
        Ok(())
    });

    sim.run()
}

#[test]
#[serial]
fn ttl() -> Result<(), RuntimeError> {
    let mut sim = SimpleSim::default();
    sim.node("192.168.2.101", || async move {
        let l = TcpListener::bind("0.0.0.0:80").await?;
        loop {
            let (_accepted, _) = l.accept().await?;
        }
    });

    sim.node("192.168.2.102", || async move {
        let stream = TcpStream::connect("192.168.2.101:80").await?;
        assert_eq!(stream.ttl()?, 64);

        tcp::set_config(Config {
            ttl: 42,
            ..Default::default()
        });
        let stream = TcpStream::connect("192.168.2.101:80").await?;
        assert_eq!(stream.ttl()?, 42);

        stream.set_ttl(32)?;
        assert_eq!(stream.ttl()?, 32);
        Ok(())
    });

    sim.run()
}
