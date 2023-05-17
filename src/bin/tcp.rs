use std::{
    fs::File,
    io::{stderr, stdout},
    sync::{atomic::AtomicUsize, Arc},
};

use des::{
    logger::{LogFormat, LogScopeConfigurationPolicy},
    net::plugin::add_plugin,
    prelude::*,
    registry,
    time::sleep,
    tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        spawn,
        task::JoinHandle,
    },
};
use inet::{
    interface::{add_interface, Interface, NetworkDevice},
    pcap::{pcap, PcapCapturePoints, PcapConfig, PcapFilters},
    tcp::{set_tcp_cfg, TcpConfig, TcpDebugPlugin},
    TcpListener, TcpStream,
};
use log::LevelFilter;

struct Connector {
    freq: f64,  // the number of bytes in the last second
    t: SimTime, // time of the last calc

    drops: Arc<AtomicUsize>,
    debug: OutVec,
    debug_p: OutVec,
}
#[async_trait::async_trait]
impl AsyncModule for Connector {
    fn new() -> Self {
        Self {
            freq: 0.0,
            t: SimTime::ZERO,
            drops: Arc::new(AtomicUsize::new(0)),
            debug_p: OutVec::new("drop".to_string(), Some(module_path())),
            debug: OutVec::new("traffic".to_string(), Some(module_path())),
        }
    }

    async fn at_sim_start(&mut self, _: usize) {
        let drops = self.drops.clone();
        spawn(async move {
            let mut recorder = OutVec::new("drops_per_sec".to_string(), Some(module_path()));
            for _i in 0..300 {
                sleep(Duration::from_secs(1)).await;
                let v = drops.swap(0, std::sync::atomic::Ordering::SeqCst);
                recorder.collect(v as f64);
            }
            recorder.finish();
        });
    }

    async fn handle_message(&mut self, msg: Message) {
        let dur = (SimTime::now() - self.t).as_secs_f64();
        if dur > 1.0 {
            self.freq = msg.header().length as f64;
            self.t = SimTime::now();
            self.debug.collect(self.freq);
        } else {
            let rem = (1.0 - dur) * self.freq;
            let n_freq = rem + msg.header().length as f64;
            self.freq = n_freq;
            self.t = SimTime::now();

            self.debug.collect(self.freq);
        }

        let prob = (self.freq / 400_000.0).min(1.0) * msg.header().length as f64 / 2000.0;
        let prob = prob.powi(5).min(1.0);
        self.debug_p.collect(prob);
        let distr = rand::distributions::Bernoulli::new(prob).unwrap();
        if sample(distr) {
            log::error!("### droping packet {}", msg.str());
            self.drops.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            return;
        }

        match msg.header().last_gate.as_ref().map(|g| g.pos()) {
            Some(0) => send(msg, ("out", 0)),
            Some(1) => send(msg, ("out", 1)),
            _ => unreachable!(),
        }
    }

    async fn at_sim_end(&mut self) {
        self.debug.finish();
        self.debug_p.finish();
    }
}

struct Client {
    handles: Vec<JoinHandle<()>>,
}
#[async_trait::async_trait]
impl AsyncModule for Client {
    fn new() -> Self {
        Self {
            handles: Vec::new(),
        }
    }

    async fn at_sim_start(&mut self, _: usize) {
        add_plugin(TcpDebugPlugin, 1);
        add_interface(Interface::ethv4(
            NetworkDevice::eth(),
            Ipv4Addr::new(69, 0, 0, 100),
        ))
        .unwrap();

        let mut cfg = TcpConfig::default();
        // cfg.debug = true;
        cfg.cong_ctrl = true;
        set_tcp_cfg(cfg).unwrap();

        for k in 0..2 {
            self.handles.push(spawn(async move {
                let mut sock = TcpStream::connect("69.0.0.69:1000").await.unwrap();
                log::info!("[{k}] opening stream");
                let mut acc = 0;
                for i in 0..1000 {
                    let n = (random::<usize>() % 2000) + 1000;
                    let x = ((i ^ n) & 0xff) as u8;
                    acc += n;
                    log::info!("[{k}] sending new byte stack [{x:x}; {n}]");
                    sock.write_all(&vec![x; n]).await.unwrap();
                    // sleep(Duration::from_secs_f64(0.025 * random::<f64>())).await;
                }
                log::info!("[{k}] closing client after {acc} bytes");
                drop(sock);
            }));
        }
    }

    async fn at_sim_end(&mut self) {
        for h in self.handles.drain(..) {
            h.await.unwrap();
        }
    }
}

struct Server {}
#[async_trait::async_trait]
impl AsyncModule for Server {
    fn new() -> Self {
        Self {}
    }

    async fn at_sim_start(&mut self, _: usize) {
        add_plugin(TcpDebugPlugin, 1);
        add_interface(Interface::ethv4(
            NetworkDevice::eth(),
            Ipv4Addr::new(69, 0, 0, 69),
        ))
        .unwrap();

        pcap(PcapConfig {
            filters: PcapFilters::default(),
            capture: PcapCapturePoints::CLIENT_DEFAULT,
            output: File::create("results/server-output.pcap").unwrap(),
        })
        .unwrap();

        let mut cfg = TcpConfig::default();
        // cfg.debug = true;
        cfg.cong_ctrl = true;
        set_tcp_cfg(cfg).unwrap();

        spawn(async move {
            let list = TcpListener::bind("0.0.0.0:1000").await.unwrap();
            loop {
                let (mut stream, from) = list.accept().await.unwrap();
                spawn(async move {
                    log::info!("got incoming connection from {from:?}");
                    let mut acc = 0;
                    loop {
                        let mut buf = [0; 1024];
                        let n = stream.read(&mut buf).await.unwrap();
                        acc += n;
                        log::info!("recevied {n} additional bytes for a total of {acc}");
                        if n == 0 {
                            break;
                        }
                    }
                    log::info!("dropping server side stream from {from:?}");
                    println!(
                        "dropping server side stream from {from:?} after {} bytes",
                        acc
                    );
                });
            }
        });
    }
}

struct Main;
impl Module for Main {
    fn new() -> Main {
        Main
    }
}

struct Policy;
impl LogScopeConfigurationPolicy for Policy {
    fn configure(&self, _scope: &str) -> (Box<dyn des::logger::LogOutput>, LogFormat, LevelFilter) {
        (
            Box::new((stdout(), stderr())),
            LogFormat::NoColor,
            LevelFilter::max(),
        )
    }
}

fn main() {
    inet::init();

    //    Logger::new().policy(Policy).set_logger();

    let mut app = NetworkApplication::new(
        NdlApplication::new(
            "src/bin/tcp.ndl",
            registry![Client, Server, Main, Connector],
        )
        .map_err(|e| println!("{e}"))
        .unwrap(),
    );
    app.include_par_file("src/bin/tcp.par");

    let rt = Runtime::new_with(app, RuntimeOptions::seeded(123).include_env());
    let _ = rt.run().unwrap();
}
