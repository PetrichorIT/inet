use std::{
    str::FromStr,
    sync::{
        atomic::{AtomicBool, AtomicU32, Ordering::SeqCst},
        Arc,
    },
};

use des::prelude::*;
use inet::{
    bsd::{AsRawFd, Fd},
    interface::*,
    tcp::TcpDebugPlugin,
    TcpListener, TcpStream,
};
use serial_test::serial;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const LIMIT: usize = 100_000;

#[NdlModule("tests")]
struct Link {}
impl Module for Link {
    fn new() -> Self {
        Self {}
    }

    fn handle_message(&mut self, msg: Message) {
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
    fd: Arc<AtomicU32>,
}

#[async_trait::async_trait]
impl AsyncModule for TcpServer {
    fn new() -> Self {
        Self {
            done: Arc::new(AtomicBool::new(false)),
            fd: Arc::new(AtomicU32::new(0)),
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
        let fd = self.fd.clone();

        tokio::spawn(async move {
            let sock = TcpListener::bind("0.0.0.0:2000").await.unwrap();
            log::info!("Server bound");
            assert_eq!(
                sock.local_addr().unwrap(),
                SocketAddr::from_str("100.100.100.100:2000").unwrap()
            );

            let (mut stream, addr) = sock.accept().await.unwrap();
            log::info!("Established stream");
            fd.store(stream.as_raw_fd(), SeqCst);
            assert_eq!(addr, SocketAddr::from_str("200.200.200.200:1024").unwrap());

            let mut buf = [0u8; 4096];
            let mut acc = 0;
            loop {
                let n = stream.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                stream.write_all(&buf[..n]).await.unwrap();
                acc += n;
            }

            assert_eq!(acc, LIMIT);

            log::info!("Server done");
            done.store(true, SeqCst);
            drop(stream);
            drop(sock);
        });
    }

    async fn handle_message(&mut self, _: Message) {
        log::error!("All packet should have been caught by the plugins");
    }

    async fn at_sim_end(&mut self) {
        assert!(self.done.load(SeqCst));

        let fd: Fd = self.fd.load(SeqCst);
        assert!(fd != 0);
        assert!(inet::bsd::bsd_socket_info(fd).is_none())
    }
}

#[NdlModule("tests")]
struct TcpClient {
    done: Arc<AtomicBool>,
    fd: Arc<AtomicU32>,
}

#[async_trait::async_trait]
impl AsyncModule for TcpClient {
    fn new() -> Self {
        Self {
            done: Arc::new(AtomicBool::new(false)),
            fd: Arc::new(AtomicU32::new(0)),
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
        let fd = self.fd.clone();

        tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            let mut stream = TcpStream::connect("100.100.100.100:2000").await.unwrap();
            fd.store(stream.as_raw_fd(), SeqCst);

            log::info!("Established stream");

            let mut acc = 0;
            // let mut waiting_to_confirm = VecDeque::with_capacity(4096);

            while acc < LIMIT {
                let k = (random::<usize>() % 4096).min(LIMIT - acc);
                let buf = std::iter::repeat_with(|| random::<u8>())
                    .take(k)
                    .collect::<Vec<_>>();

                stream.write_all(&buf).await.unwrap();
                let mut ret = vec![0u8; k];
                stream.read_exact(&mut ret).await.unwrap();

                assert_eq!(buf, ret);
                acc += k;
            }

            log::info!("Client done");
            done.store(true, SeqCst);
            drop(stream);
        });
    }

    async fn handle_message(&mut self, _: Message) {
        panic!("All packet should have been caught by the plugins")
    }

    async fn at_sim_end(&mut self) {
        assert!(self.done.load(SeqCst));

        let fd: Fd = self.fd.load(SeqCst);
        assert!(fd != 0);
        assert!(inet::bsd::bsd_socket_info(fd).is_none())
    }
}

#[NdlSubsystem("tests")]
struct Main {}

#[test]
#[serial]
fn tcp_echo_100k() {
    inet::init();

    // ScopedLogger::new()
    //     .interal_max_log_level(log::LevelFilter::Warn)
    //     .finish()
    //     .unwrap();

    let app = Main {}.build_rt();
    let rt = Runtime::new_with(
        app,
        RuntimeOptions::seeded(123), // .max_itr(100)
                                     // .max_time(SimTime::from_duration(Duration::from_secs(3))),
    );
    let (_, time, profiler) = rt.run().unwrap();
    assert_eq!(time.as_secs(), 11);
    assert!(profiler.event_count < 5000);
}
