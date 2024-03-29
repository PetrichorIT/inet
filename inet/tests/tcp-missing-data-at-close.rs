use bytepack::FromBytestream;
use des::registry;
use inet_types::{ip::Ipv4Packet, tcp::TcpPacket};
use std::{
    str::FromStr,
    sync::{
        atomic::{AtomicBool, AtomicU32, Ordering::SeqCst},
        Arc,
    },
};

use des::prelude::*;
use inet::{interface::*, socket::AsRawFd, TcpSocket};

#[derive(Default)]
struct Link {}
impl Module for Link {
    fn handle_message(&mut self, msg: Message) {
        // random packet drop 10 %
        if (random::<usize>() % 10) == 7 {
            let ippacket = msg.content::<Ipv4Packet>();
            let tcp = TcpPacket::from_slice(&ippacket.content).unwrap();

            tracing::error!(
                "DROP {} --> {} :: Tcp {{ {} seq_no = {} ack_no = {} win = {} data = {} bytes }}",
                ippacket.src,
                ippacket.dest,
                tcp.flags,
                tcp.seq_no,
                tcp.ack_no,
                tcp.window,
                tcp.content.len(),
            );

            return;
        }

        match msg.header().last_gate.as_ref().map(|v| v.name()) {
            Some("lhs") => send(msg, "rhs"),
            Some("rhs") => send(msg, "lhs"),
            _ => todo!(),
        }
    }
}

#[derive(Default)]
struct TcpServer {
    done: Arc<AtomicBool>,
    fd: Arc<AtomicU32>,
}

impl AsyncModule for TcpServer {
    async fn at_sim_start(&mut self, _: usize) {
        add_interface(Interface::ethv4(
            NetworkDevice::eth(),
            Ipv4Addr::new(69, 0, 0, 100),
        ))
        .unwrap();

        // inet::pcap::pcap(inet::pcap::PcapConfig {
        //     filters: inet::pcap::PcapFilters::default(),
        //     capture: inet::pcap::PcapCapturePoints::CLIENT_DEFAULT,
        //     output: std::fs::File::create("server.pcap").unwrap(),
        // })
        // .unwrap();

        let done = self.done.clone();
        let fd = self.fd.clone();

        tokio::spawn(async move {
            let sock = TcpSocket::new_v4().unwrap();
            sock.bind(SocketAddr::from_str("0.0.0.0:2000").unwrap())
                .unwrap();

            sock.set_send_buffer_size(1024).unwrap();
            sock.set_recv_buffer_size(1024).unwrap();

            let sock = sock.listen(1024).unwrap();

            // let sock = TcpListener::bind("0.0.0.0:2000").await.unwrap();
            tracing::info!("Server bound");

            let (mut stream, _) = sock.accept().await.unwrap();
            tracing::info!("Established stream");

            fd.store(stream.as_raw_fd(), SeqCst);

            // let mut buf = [0u8; 100];
            // let err = stream.try_read(&mut buf).unwrap_err();
            // assert_eq!(err.kind(), ErrorKind::WouldBlock);

            use tokio::io::AsyncReadExt;
            let mut buf = [0u8; 500];
            let mut acc = 0;
            loop {
                let Ok(n) = stream.read(&mut buf).await else {
                    break;
                };
                tracing::info!("received {} bytes", n);

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

            let n = stream.read(&mut buf).await.unwrap();
            assert_eq!(n, 0);

            tracing::info!("Server done");
            drop(stream);
            drop(sock);

            done.store(true, SeqCst);
        });
    }

    async fn handle_message(&mut self, _: Message) {
        tracing::error!("HM?");
    }

    async fn at_sim_end(&mut self) {
        use inet::socket::bsd_socket_info;

        assert!(self.done.load(SeqCst));
        assert!(bsd_socket_info(self.fd.load(SeqCst)).is_err());
    }
}

#[derive(Default)]
struct TcpClient {
    done: Arc<AtomicBool>,
    fd: Arc<AtomicU32>,
}

impl AsyncModule for TcpClient {
    async fn at_sim_start(&mut self, _: usize) {
        add_interface(Interface::ethv4(
            NetworkDevice::eth(),
            Ipv4Addr::new(69, 0, 0, 200),
        ))
        .unwrap();

        // inet::pcap::pcap(inet::pcap::PcapConfig {
        //     filters: inet::pcap::PcapFilters::default(),
        //     capture: inet::pcap::PcapCapturePoints::CLIENT_DEFAULT,
        //     output: std::fs::File::create("client.pcap").unwrap(),
        // })
        // .unwrap();

        let done = self.done.clone();
        let fd = self.fd.clone();

        tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            let sock = TcpSocket::new_v4().unwrap();
            sock.set_send_buffer_size(1024).unwrap();
            sock.set_recv_buffer_size(1024).unwrap();

            let mut stream = sock
                .connect(SocketAddr::from_str("69.0.0.100:2000").unwrap())
                .await
                .unwrap();

            fd.store(stream.as_raw_fd(), SeqCst);

            tracing::info!("Established stream");

            let buf = vec![42; 2000];
            stream.write_all(&buf).await.unwrap();

            tracing::info!("Client done");
            drop(stream);

            done.store(true, SeqCst);
        });
    }

    async fn handle_message(&mut self, _: Message) {
        panic!()
    }

    async fn at_sim_end(&mut self) {
        use inet::socket::bsd_socket_info;

        assert!(self.done.load(SeqCst));
        assert!(bsd_socket_info(self.fd.load(SeqCst)).is_err());
    }
}

#[test]
#[serial_test::serial]
fn tcp_missing_data_at_close() {
    inet::init();

    // Subscriber::default()
    //     .with_max_level(LevelFilter::TRACE)
    //     .init()
    //     .unwrap();

    let app = Sim::ndl(
        "tests/tcp.ndl",
        registry![Link, TcpServer, TcpClient, else _],
    )
    .map_err(|e| println!("{e}"))
    .unwrap();
    let rt = Builder::seeded(1263431312323)
        .max_time(10.0.into())
        .build(app);
    let _ = rt.run().unwrap();
}
