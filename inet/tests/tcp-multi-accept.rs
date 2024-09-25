//! Tests whether one active TcpListener::accept blocks
//! any progress on any other handshakes

use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

use des::{prelude::*, registry};
use inet::{
    interface::{add_interface, Interface, NetworkDevice},
    TcpListener, TcpStream,
};
use tokio::spawn;

#[derive(Default)]
struct Client {
    done: Arc<AtomicBool>,
}

impl Module for Client {
    fn at_sim_start(&mut self, _: usize) {
        add_interface(Interface::ethv4(
            NetworkDevice::eth(),
            Ipv4Addr::new(192, 168, 0, 1),
        ))
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

    fn at_sim_end(&mut self) {
        assert!(self.done.load(Ordering::SeqCst));
    }
}

#[derive(Default)]
struct Server {
    done: Arc<AtomicBool>,
}

impl Module for Server {
    fn at_sim_start(&mut self, _: usize) {
        add_interface(Interface::ethv4(
            NetworkDevice::eth(),
            Ipv4Addr::new(192, 168, 0, 2),
        ))
        .unwrap();

        let done = self.done.clone();
        spawn(async move {
            let lis = TcpListener::bind("0.0.0.0:80").await.unwrap();
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

    fn at_sim_end(&mut self) {
        assert!(self.done.load(Ordering::SeqCst));
    }
}

#[test]
fn tcp_multi_accept() {
    // des::tracing::init();

    let app = Sim::new(())
        .with_stack(inet::init)
        .with_ndl(
            "tests/tcp-multi-accept.yml",
            registry![Server, Client, else _],
        )
        .map_err(|e| println!("{e}"))
        .unwrap();
    let rt = Builder::seeded(123).build(app);
    let (_, t, _) = rt.run().unwrap();
    assert!(t < 3.0.into());
}
