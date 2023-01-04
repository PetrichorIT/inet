use std::str::FromStr;
use std::sync::{
    atomic::{AtomicBool, Ordering::SeqCst},
    Arc,
};

use des::prelude::*;
use inet::{
    interface::*,
    ip::Ipv4Packet,
    tcp::{TcpDebugPlugin, TcpPacket},
    FromBytestream, TcpSocket,
};

#[NdlModule("tests")]
struct Link {}
impl Module for Link {
    fn new() -> Self {
        Self {}
    }

    fn handle_message(&mut self, msg: Message) {
        // random packet drop 10 %
        if (random::<usize>() % 10) == 7 {
            let ippacket = msg.content::<Ipv4Packet>();
            let tcp = TcpPacket::from_buffer(&ippacket.content).unwrap();

            log::error!(
                "DROP {} --> {} :: Tcp {{ {} seq_no = {} ack_no = {} win = {} }}",
                ippacket.src,
                ippacket.dest,
                tcp.flags,
                tcp.seq_no,
                tcp.ack_no,
                tcp.window
            );

            return;
        }

        match msg.header().last_gate.as_ref().map(|v| v.name()) {
            Some("lhs_in") => send(msg, "rhs_out"),
            Some("rhs_in") => send(msg, "lhs_out"),
            _ => todo!(),
        }
    }
}

#[NdlModule("tests")]
struct TcpServer {
    done: Arc<AtomicBool>,
}
#[async_trait::async_trait]
impl AsyncModule for TcpServer {
    fn new() -> Self {
        Self {
            done: Arc::new(AtomicBool::new(false)),
        }
    }
    async fn at_sim_start(&mut self, _: usize) {
        add_plugin(TcpDebugPlugin, 1);

        add_interface(Interface::en0(
            random(),
            Ipv4Addr::new(100, 100, 100, 100),
            NetworkDevice::eth_default(),
        ));

        let done = self.done.clone();
        tokio::spawn(async move {
            let sock = TcpSocket::new_v4().unwrap();
            sock.bind(SocketAddr::from_str("0.0.0.0:2000").unwrap())
                .unwrap();

            sock.set_send_buffer_size(1024).unwrap();
            sock.set_recv_buffer_size(1024).unwrap();

            let sock = sock.listen(1024).unwrap();

            // let sock = TcpListener::bind("0.0.0.0:2000").await.unwrap();
            log::info!("Server bound");

            let (mut stream, _) = sock.accept().await.unwrap();
            log::info!("Established stream");

            // Expect fast open
            let mut buf = [0u8; 100];
            let n = stream.try_read(&mut buf).unwrap();

            use tokio::io::AsyncReadExt;
            let mut buf = [0u8; 500];
            let mut acc = n;
            loop {
                let Ok(n) = stream.read(&mut buf).await else { break };
                log::info!("received {} bytes", n);

                if n == 0 {
                    // Socket closed
                    break;
                } else {
                    acc += n;
                    if acc == 2000 {
                        break;
                    }
                };
            }

            let t = SimTime::now();
            let d = SimTime::from_duration(Duration::from_secs(1)) - t;
            log::info!("Waiting for {d:?}");
            tokio::time::sleep(d).await;

            log::info!("Server done");
            drop(stream);
            drop(sock);

            done.store(true, SeqCst);
        });
    }

    async fn handle_message(&mut self, _: Message) {
        log::error!("HM?");
    }

    async fn at_sim_end(&mut self) {
        assert!(self.done.load(SeqCst));
    }
}

#[NdlModule("tests")]
struct TcpClient {
    done: Arc<AtomicBool>,
}
#[async_trait::async_trait]
impl AsyncModule for TcpClient {
    fn new() -> Self {
        Self {
            done: Arc::new(AtomicBool::new(false)),
        }
    }
    async fn at_sim_start(&mut self, _: usize) {
        add_plugin(TcpDebugPlugin, 1);

        add_interface(Interface::en0(
            random(),
            Ipv4Addr::new(200, 200, 200, 200),
            NetworkDevice::eth_default(),
        ));

        let done = self.done.clone();
        tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            let sock = TcpSocket::new_v4().unwrap();
            sock.set_send_buffer_size(1024).unwrap();
            sock.set_recv_buffer_size(1024).unwrap();

            let mut stream = sock
                .connect(SocketAddr::from_str("100.100.100.100:2000").unwrap())
                .await
                .unwrap();

            log::info!("Established stream");

            let buf = vec![42; 2000];
            stream.write_all(&buf).await.unwrap();

            let t = SimTime::now();
            let d = SimTime::from_duration(Duration::from_secs(1)) - t;
            log::info!("Waiting for {d:?}");
            tokio::time::sleep(d).await;

            log::info!("Client done");
            drop(stream);

            done.store(true, SeqCst);
        });
    }

    async fn handle_message(&mut self, _: Message) {
        panic!()
    }

    async fn at_sim_end(&mut self) {
        assert!(self.done.load(SeqCst));
    }
}

#[NdlSubsystem("tests")]
struct Main {}

#[test]
#[serial_test::serial]
fn tcp_accidental_fast_open() {
    inet::init();

    // ScopedLogger::new()
    //     .interal_max_log_level(log::LevelFilter::Warn)
    //     .finish()
    //     .unwrap();

    let app = Main {}.build_rt();
    let rt = Runtime::new_with(
        app,
        RuntimeOptions::seeded(123)
            // .max_itr(100)
            .max_time(SimTime::from_duration(Duration::from_secs(3))),
    );
    let _ = rt.run();
}
