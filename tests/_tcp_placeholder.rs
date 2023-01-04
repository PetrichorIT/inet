use des::prelude::*;
use inet::{
    interface::*,
    ip::Ipv4Packet,
    tcp::{TcpDebugPlugin, TcpPacket},
    FromBytestream,
};
use std::sync::{
    atomic::{AtomicBool, Ordering::SeqCst},
    Arc,
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
            // [[ SERVER CODE HERE

            //    SERVER CODE HERE ]]
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
            // [[ CLIENT CODE HERE

            //    CLIENT CODE HERE ]]
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
fn _tcp_placeholder() {
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
    let _ = rt.run().unwrap();
}
