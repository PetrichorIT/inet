use std::{error::Error, net::Ipv4Addr, time::Duration};

use des::{net::Sim, prelude::Module, registry, runtime::Builder, time::sleep};
use inet::{
    interface::{add_interface, Interface, NetworkDevice},
    tcp2::{TcpListener, TcpStream},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    spawn,
};

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

            sock.writable().await.unwrap();
            tracing::info!("WRITABLE");
            sleep(Duration::from_secs(1)).await;
            tracing::info!("DO WRITE");

            sock.write(b"Hello world").await.unwrap()
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
            while let Ok((mut sock, from)) = list.accept().await {
                tracing::info!("INCOMING SOCK: {from}");
                sock.readable().await.unwrap();
                tracing::info!("CAN READ");
                let mut buf = [0; 16];
                let n = sock.read(&mut buf).await.unwrap();
                tracing::info!("read {n} bytes '{}'", String::from_utf8_lossy(&buf));
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
