use std::{error::Error, net::Ipv4Addr};

use des::{net::Sim, prelude::Module, registry, runtime::Builder};
use inet::{
    interface::{add_interface, Interface, NetworkDevice},
    tcp2::{api::TcpStream, TcpListener},
};
use tokio::{io::AsyncWriteExt, spawn};

#[derive(Default)]
struct Client;
#[derive(Default)]
struct Server;

impl Module for Client {
    fn at_sim_start(&mut self, _stage: usize) {
        add_interface(Interface::ethv4(
            NetworkDevice::eth(),
            Ipv4Addr::new(69, 0, 0, 100),
        ))
        .unwrap();

        spawn(async move {
            let mut sock = TcpStream::connect("69.0.0.69:8000").await.unwrap();
            tracing::info!("SOCK ESTAB");
            sock.write_all(b"Hello world").await.unwrap()
        });
    }
}

impl Module for Server {
    fn at_sim_start(&mut self, _stage: usize) {
        add_interface(Interface::ethv4(
            NetworkDevice::eth(),
            Ipv4Addr::new(69, 0, 0, 69),
        ))
        .unwrap();

        spawn(async move {
            let list = TcpListener::bind("0.0.0.0:8000").await.unwrap();
            while let Ok((_sock, from)) = list.accept().await {
                tracing::info!("INCOMING SOCK: {from}")
            }
        });
    }
}

#[test]
fn main() -> Result<(), Box<dyn Error>> {
    des::tracing::init();

    let sim = Sim::new(())
        .with_stack(inet::init)
        .with_ndl("tests/tcp2.yml", registry![Client, Server, else _])?;

    let _ = Builder::seeded(123)
        .max_time(100.0.into())
        .build(sim)
        .run()
        .unwrap();

    Ok(())
}
