//! Tests whether one active TcpListener::accept blocks
//! any progress on any other handshakes

use des::{prelude::*, registry};
use inet::{
    interface::{add_interface, Interface, NetworkDevice},
    TcpSocket, TcpStream,
};
use tokio::{spawn, task::JoinHandle};

#[derive(Default)]
struct Client {
    handle: Option<JoinHandle<()>>,
}

impl AsyncModule for Client {
    async fn at_sim_start(&mut self, _: usize) {
        add_interface(Interface::ethv4(
            NetworkDevice::eth(),
            Ipv4Addr::new(192, 168, 0, 1),
        ))
        .unwrap();

        self.handle = Some(spawn(async {
            for _ in 0..10 {
                spawn(async {
                    let sock = TcpStream::connect("192.168.0.2:80").await;
                    tracing::info!("{sock:?}");
                });
            }
        }));
    }

    async fn at_sim_end(&mut self) {
        self.handle.take().unwrap().await.unwrap();
    }
}

#[derive(Default)]
struct Server {
    handle: Option<JoinHandle<()>>,
}

impl AsyncModule for Server {
    async fn at_sim_start(&mut self, _: usize) {
        add_interface(Interface::ethv4(
            NetworkDevice::eth(),
            Ipv4Addr::new(192, 168, 0, 2),
        ))
        .unwrap();

        self.handle = Some(spawn(async {
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
        }));
    }

    async fn at_sim_end(&mut self) {
        self.handle.take().unwrap().await.unwrap();
    }
}

#[test]
fn tcp_listen_backlog() {
    inet::init();

    // Logger::new().set_logger();

    let app = Sim::ndl(
        "tests/tcp-multi-accept.ndl",
        registry![Server, Client, else _],
    )
    .map_err(|e| println!("{e}"))
    .unwrap();
    let rt = Builder::seeded(123).build(app);
    let (_, t, _) = rt.run().unwrap();
    assert!(t > 3.0.into());
}
