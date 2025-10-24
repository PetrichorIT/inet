use std::time::Duration;

use des::{
    net::{
        globals,
        module::{Prop, PropType},
    },
    prelude::current,
    runtime::{RuntimeError, random},
    time::sleep,
};
use serial_test::serial;

use crate::test_util::SimpleSim;

use super::UdpSocket;

mod bind;
mod broadcast;
mod cancel;
mod connect;
mod peek;
mod recv;
mod send;

#[test]
#[serial]
fn ping_pong() -> Result<(), RuntimeError> {
    let mut sim = SimpleSim::default();
    sim.node("192.168.2.100", || async move {
        let out = std::iter::repeat_with(|| random())
            .take(4098)
            .collect::<Vec<_>>();
        let mut echoed = Vec::<u8>::with_capacity(4098);

        sleep(Duration::from_secs(1)).await;

        let socket = UdpSocket::bind("0.0.0.0:100").await.unwrap();
        socket.connect("192.168.2.101:200").await.unwrap();

        let mut cursor = 0;
        let mut c = 0;
        while cursor < out.len() {
            let remaning = out.len() - cursor;
            let size = random::<u64>() as usize % (1024.min(remaning));
            let size = size.max(256).min(remaning);

            socket.send(&out[cursor..(cursor + size)]).await.unwrap();
            cursor += size;

            let d = Duration::from_secs_f64(random::<f64>());
            sleep(d).await;
            c += 1;
        }

        tracing::info!("send all {c} packets");

        loop {
            if echoed.len() >= out.len() {
                break;
            }
            // Receive contents
            let mut buf = [0u8; 1024];
            let n = socket.recv(&mut buf).await.unwrap();
            echoed.extend(&buf[..n]);
        }

        Ok(())
    });

    sim.node("192.168.2.101", || async move {
        let socket = UdpSocket::bind("0.0.0.0:200").await.unwrap();
        let mut acc = 0;
        while acc < 4098 {
            let mut buf = [0u8; 1024];
            let (n, from) = socket.recv_from(&mut buf).await.unwrap();
            acc += n;
            socket.send_to(&buf[..n], from).await.unwrap();
        }
        Ok(())
    });

    sim.run()
}

impl PropType for UdpSocket {
    fn as_value(&self) -> serde_yml::Value {
        serde_yml::Value::Null
    }

    fn from_value(_: serde_yml::Value) -> Result<Self, des::net::Error>
    where
        Self: Sized,
    {
        Err(des::net::Error::new_current(des::net::ErrorKind::Other))
    }
}

#[test]
#[serial]
fn inspect_foreign_io_object() -> Result<(), RuntimeError> {
    let mut sim = SimpleSim::default();
    sim.node("192.168.2.100", || async move {
        let sock = UdpSocket::bind("0.0.0.0:0").await?;
        assert_eq!(sock.local_addr()?.port(), 1024);
        current().prop("sock").unwrap().set(sock);
        Ok(())
    });

    sim.node("192.168.2.101", || async move {
        sleep(Duration::from_secs(1)).await;

        let foreign: Prop<UdpSocket, true> = globals()
            .get(&"192_168_2_100".into())
            .unwrap()
            .prop("sock")
            .unwrap()
            .expect("has value");

        assert_eq!(foreign.map(|sock| sock.local_addr())?.port(), 1024);

        Ok(())
    });

    sim.run()
}

#[test]
#[serial]
fn default_ttl() -> Result<(), RuntimeError> {
    let mut sim = SimpleSim::default();
    sim.node("alice", || async move {
        let sock = UdpSocket::bind("0.0.0.0:0").await?;
        assert_eq!(sock.ttl()?, 32);
        Ok(())
    });

    sim.run()
}
