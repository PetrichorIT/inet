//! Tests whether one active TcpListener::accept blocks
//! any progress on any other handshakes

use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use des::prelude::*;
use des_ndl::{Ndl, registry};
use inet::{
    interface::{InterfaceDef, NetworkDevice},
    ioctx,
    tcp::{TcpSocket, TcpStream},
};
use tokio::spawn;

#[derive(Default)]
struct Client {
    done: Arc<AtomicBool>,
}

impl Module for Client {
    fn at_sim_start(&mut self, _: usize) {
        ioctx()
            .add_interface(
                InterfaceDef::new("en0", NetworkDevice::eth())
                    .ip(Ipv4Addr::new(192, 168, 0, 1).into()),
            )
            .unwrap();

        let done = self.done.clone();
        spawn(async move {
            for _ in 0..10 {
                spawn(async {
                    let sock = TcpStream::connect("192.168.0.2:80").await;
                    tracing::info!("{sock:?}");
                });
            }
            done.store(true, Ordering::SeqCst);
        });
    }

    fn at_sim_end(&mut self) -> Result<(), des::net::Error> {
        assert!(self.done.load(Ordering::SeqCst));
        Ok(())
    }
}

#[derive(Default)]
struct Server {
    done: Arc<AtomicBool>,
}

impl Module for Server {
    fn at_sim_start(&mut self, _: usize) {
        ioctx()
            .add_interface(
                InterfaceDef::new("en0", NetworkDevice::eth())
                    .ip(Ipv4Addr::new(192, 168, 0, 2).into()),
            )
            .unwrap();

        let done = self.done.clone();
        spawn(async move {
            let sock = TcpSocket::new_v4().unwrap();
            sock.bind("0.0.0.0:80".parse().unwrap()).unwrap();
            let lis = sock.listen(5).unwrap();
            let mut c = 0;
            while let Ok(stream) = lis.accept().await {
                tracing::info!("receiving tcp stream {stream:?}");
                c += 1;
                if c == 10 {
                    break;
                }
            }
            done.store(true, Ordering::SeqCst);
        });
    }

    fn at_sim_end(&mut self) -> Result<(), des::net::Error> {
        assert!(self.done.load(Ordering::SeqCst));
        Ok(())
    }
}

#[test]
fn tcp_listen_backlog() -> Result<(), Box<dyn std::error::Error>> {
    // des::tracing::init();

    let mut app = Sim::new(()).with_stack(inet::init);
    let def = serde_norway::from_str(include_str!("tcp-multi-accept.yml"))?;
    app.node("", Ndl::new(&mut registry![Server, Client, else _], &def)?)?;

    let rt = Builder::seeded(123).build(app.freeze());
    let r = rt.run().assert_no_err();
    assert!(r.time > 3.0.into());
    Ok(())
}
