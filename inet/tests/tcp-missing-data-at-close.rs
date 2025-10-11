use bytes_io::FromBytes;
use des::{registry, time::sleep};
use std::{
    str::FromStr,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU32, Ordering::SeqCst},
    },
};
use types::{ip::Ipv4Packet, tcp::TcpPacket};

use des::prelude::*;
use inet::{interface::*, ioctx, socket::AsRawFd, tcp::TcpSocket};

#[derive(Default)]
struct Link {}
impl Module for Link {
    fn handle_message(&mut self, msg: Message) {
        // random packet drop 10 %
        if (random::<u64>() as usize % 10) == 7 && msg.body.is::<Ipv4Packet>() {
            let ippacket = msg.body.content::<Ipv4Packet>();
            let tcp = TcpPacket::peek_from(&ippacket.content[..]).unwrap();

            tracing::error!(
                "DROP {} --> {} :: Tcp {{ {:?} seq_no = {} ack_no = {} win = {} data = {} bytes }}",
                ippacket.src,
                ippacket.dst,
                tcp.flags,
                tcp.seq_no,
                tcp.ack_no,
                tcp.window,
                tcp.content.len(),
            );

            return;
        }

        let _ = match msg.header.last_gate.as_ref().map(|v| v.name()) {
            Some("lhs") => send(msg, "rhs"),
            Some("rhs") => send(msg, "lhs"),
            _ => todo!(),
        };
    }
}

#[derive(Default)]
struct TcpServer {
    done: Arc<AtomicBool>,
    fd: Arc<AtomicU32>,
}

impl Module for TcpServer {
    fn at_sim_start(&mut self, _: usize) {
        ioctx()
            .add_interface(
                InterfaceDef::new("en0", NetworkDevice::eth())
                    .ip(Ipv4Addr::new(69, 0, 0, 100).into()),
            )
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
            sock.set_maximum_segement_size(536).unwrap();
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

            sleep(Duration::from_secs(10)).await;

            done.store(true, SeqCst);
        });
    }

    fn handle_message(&mut self, _: Message) {
        tracing::error!("HM?");
    }

    fn at_sim_end(&mut self) -> Result<(), RuntimeError> {
        use inet::socket::bsd_socket_info;

        assert!(self.done.load(SeqCst));
        assert!(bsd_socket_info(self.fd.load(SeqCst)).is_err());
        Ok(())
    }
}

#[derive(Default)]
struct TcpClient {
    done: Arc<AtomicBool>,
    fd: Arc<AtomicU32>,
}

impl Module for TcpClient {
    fn at_sim_start(&mut self, _: usize) {
        ioctx()
            .add_interface(
                InterfaceDef::new("en0", NetworkDevice::eth())
                    .ip(Ipv4Addr::new(69, 0, 0, 200).into()),
            )
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
            sock.set_maximum_segement_size(536).unwrap();
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

    fn at_sim_end(&mut self) -> Result<(), RuntimeError> {
        use inet::socket::bsd_socket_info;

        assert!(self.done.load(SeqCst));
        assert!(bsd_socket_info(self.fd.load(SeqCst)).is_err());
        Ok(())
    }
}

#[test]
#[serial_test::serial]
fn tcp_missing_data_at_close() -> Result<(), RuntimeError> {
    // des::tracing::init();

    let def = serde_yml::from_str(include_str!("tcp.yml"))?;
    let mut app = Sim::new(()).with_stack(inet::init);
    app.nodes_from_ndl(&def, registry![Link, TcpServer, TcpClient, else _])?;
    let rt = Builder::seeded(1263431312323)
        .max_time(20.0.into())
        .build(app.freeze());
    rt.run().map(|_| ())
}
