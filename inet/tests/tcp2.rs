use std::{error::Error, net::Ipv4Addr, time::Duration};

use des::{net::Sim, prelude::Module, runtime::Builder, time::sleep};
use des_ndl::{Ndl, registry};
use inet::{
    interface::{InterfaceDef, NetworkDevice},
    ioctx,
    tcp::{TcpListener, TcpStream},
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
        ioctx()
            .add_interface(
                InterfaceDef::new("en0", NetworkDevice::eth())
                    .ip(Ipv4Addr::new(69, 0, 0, 100).into()),
            )
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
        ioctx()
            .add_interface(
                InterfaceDef::new("en0", NetworkDevice::eth())
                    .ip(Ipv4Addr::new(69, 0, 0, 69).into()),
            )
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
    // des::tracing::init();

    let mut app = Sim::new(()).with_stack(inet::init);
    let def = serde_norway::from_str(include_str!("tcp2.yml"))?;
    app.node("", Ndl::new(&mut registry![Client, Server, else _], &def)?)?;

    let _ = Builder::seeded(123)
        .max_time(100.0.into())
        .build(app.freeze())
        .run()
        .assert_no_err();

    Ok(())
}
