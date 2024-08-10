use des::registry;
use std::{
    io::ErrorKind,
    str::FromStr,
    sync::{
        atomic::{AtomicBool, AtomicU32, Ordering::SeqCst},
        Arc,
    },
};

use des::prelude::*;
use inet::{
    interface::*,
    socket::{AsRawFd, Fd},
    TcpSocket,
};

#[derive(Default)]
struct Link {}
impl Module for Link {
    fn handle_message(&mut self, msg: Message) {
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

impl Module for TcpServer {
    fn at_sim_start(&mut self, _: usize) {
        add_interface(Interface::ethv4(
            NetworkDevice::eth(),
            Ipv4Addr::new(69, 0, 0, 100),
        ))
        .unwrap();

        let done = self.done.clone();
        let fd = self.fd.clone();

        tokio::spawn(async move {
            let sock = TcpSocket::new_v4().unwrap();
            sock.bind(SocketAddr::from_str("0.0.0.0:2000").unwrap())
                .unwrap();

            sock.set_send_buffer_size(1024).unwrap();
            sock.set_recv_buffer_size(1024).unwrap();

            let sock = sock.listen(1024).unwrap();
            tracing::info!("Server bound");
            assert_eq!(
                sock.local_addr().unwrap(),
                SocketAddr::from_str("0.0.0.0:2000").unwrap()
            );

            let (mut stream, addr) = sock.accept().await.unwrap();
            tracing::info!("Established stream");
            fd.store(stream.as_raw_fd(), SeqCst);
            assert_eq!(addr, SocketAddr::from_str("69.0.0.200:1024").unwrap());

            let mut buf = [0u8; 100];
            let err = stream.try_read(&mut buf).unwrap_err();
            assert_eq!(err.kind(), ErrorKind::WouldBlock);

            use tokio::io::AsyncReadExt;

            let mut buf = [0u8; 800];
            let n = stream.read(&mut buf).await.unwrap();
            tracing::info!("recv {n} bytes");
            assert_eq!(n, 800); // Freed 800 bytes (ACK send)

            let t0 = SimTime::now();

            let mut buf = [0u8; 1200];
            let n = stream.read_exact(&mut buf).await.unwrap();
            tracing::info!("recv {n} bytes");
            assert_eq!(n, 1200);

            let t1 = SimTime::now();
            assert_ne!(t0, t1);

            // This seed is generated on the run of tcp_partial_mtu_at_simultaneous_close
            let seed_derived = random::<usize>();
            if seed_derived == 5270976807191845495 {
                // NOP
                // causes sim close
            } else {
                // Just to keep the server alive
                // and prevent a simultaneous close
                let n = stream.read(&mut buf).await.unwrap();
                assert_eq!(n, 0);
            }

            tracing::info!("Server done");
            done.store(true, SeqCst);
            drop(stream);
            drop(sock);
        });
    }

    fn handle_message(&mut self, _: Message) {
        tracing::error!("All packet should have been caught by the plugins");
    }

    fn at_sim_end(&mut self) {
        assert!(self.done.load(SeqCst));

        let fd: Fd = self.fd.load(SeqCst);
        assert!(fd != 0);
        assert!(inet::socket::bsd_socket_info(fd).is_err())
    }
}

#[derive(Default)]
struct TcpClient {
    done: Arc<AtomicBool>,
    fd: Arc<AtomicU32>,
}

impl Module for TcpClient {
    fn at_sim_start(&mut self, _: usize) {
        add_interface(Interface::ethv4(
            NetworkDevice::eth(),
            Ipv4Addr::new(69, 0, 0, 200),
        ))
        .unwrap();

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

            // let mut stream = TcpStream::connect("100.100.100.100:2000").await.unwrap();
            fd.store(stream.as_raw_fd(), SeqCst);

            tracing::info!("Established stream");

            let buf = vec![42; 2000];
            stream.write_all(&buf).await.unwrap();

            tracing::info!("Client done");
            done.store(true, SeqCst);
            drop(stream);
        });
    }

    fn handle_message(&mut self, _: Message) {
        panic!("All packet should have been caught by the plugins")
    }

    fn at_sim_end(&mut self) {
        assert!(self.done.load(SeqCst));

        let fd: Fd = self.fd.load(SeqCst);
        assert!(fd != 0);
        assert!(inet::socket::bsd_socket_info(fd).is_err())
    }
}

#[test]
#[serial_test::serial]
fn tcp_partial_mtu_at_default_close() {
    let app = Sim::new(())
        .with_stack(inet::init)
        .with_ndl(
            "tests/tcp.ndl",
            registry![Link, TcpServer, TcpClient, else _],
        )
        .map_err(|e| println!("{e}"))
        .unwrap();
    let rt = Builder::seeded(123).max_time(3.0.into()).build(app);
    let (_, time, profiler) = rt.run().unwrap();
    assert_eq!(time.as_secs(), 1);
    assert!(profiler.event_count < 200);
}

#[test]
#[serial_test::serial]
fn tcp_partial_mtu_at_simultaneous_close() {
    // ScopedLogger::new()
    //     .interal_max_log_level(tracing::LevelFilter::Warn)
    //     .finish()
    //     .unwrap();

    let app = Sim::new(())
        .with_stack(inet::init)
        .with_ndl(
            "tests/tcp.ndl",
            registry![Link, TcpServer, TcpClient, else _],
        )
        .map_err(|e| println!("{e}"))
        .unwrap();
    let rt = Builder::seeded(999999999).max_time(3.0.into()).build(app);
    let (_, time, profiler) = rt.run().unwrap();
    assert_eq!(time.as_secs(), 1);
    assert!(profiler.event_count < 200);
}
