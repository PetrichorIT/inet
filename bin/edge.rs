use des::tokio::io::{AsyncReadExt, AsyncWriteExt};

use des::prelude::*;
use inet::{
    interface::{add_interface, Interface, NetworkDevice},
    TcpListener, TcpStream,
};

#[NdlModule("bin")]
pub struct EdgeNode {}

#[async_trait::async_trait]
impl AsyncModule for EdgeNode {
    fn new() -> Self {
        Self {}
    }

    async fn at_sim_start(&mut self, _stage: usize) {
        let ip = par("addr").unwrap().parse::<IpAddr>().unwrap();

        add_interface(Interface::ethernet(&[ip], NetworkDevice::eth_default()));
        add_interface(Interface::loopback());

        if format!("{ip}") == "100.100.1.102" || format!("{ip}") == "100.100.3.101" {
            des::tokio::spawn(async move {
                let d = random::<f64>() / 2.0;
                des::tokio::time::sleep(Duration::from_secs_f64(d)).await;

                log::info!("Opening socket");
                let mut stream = TcpStream::connect("200.200.2.201:80").await.unwrap();

                let wbuf = [42u8; 1500];
                stream.write_all(&wbuf).await.unwrap();

                let mut rbuf = [0u8; 1500];
                stream.read_exact(&mut rbuf).await.unwrap();

                assert_eq!(rbuf, wbuf);

                log::info!("done");
            });
        }

        if format!("{ip}") == "200.200.2.201" {
            des::tokio::spawn(async move {
                let listener = TcpListener::bind("0.0.0.0:80").await.unwrap();
                while let Ok((mut stream, _peer)) = listener.accept().await {
                    des::tokio::spawn(async move {
                        let mut buf = [0u8; 2048];
                        loop {
                            let Ok(n) = stream.read(&mut buf).await else {
                                break
                            };

                            if n == 0 {
                                break;
                            }

                            let _ = stream.write_all(&buf[..n]).await;
                        }
                    });
                }
            });
        }
    }

    async fn handle_message(&mut self, msg: Message) {
        log::info!("received {}", msg.str())
    }
}
