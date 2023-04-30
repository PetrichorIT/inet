use des::{
    net::plugin::add_plugin,
    prelude::*,
    registry,
    tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        spawn,
        task::JoinHandle,
    },
};
use inet::{
    interface::{add_interface, Interface, NetworkDevice},
    tcp::{set_tcp_cfg, TcpConfig, TcpDebugPlugin},
    TcpListener, TcpStream,
};

struct Connector {
    freq: f64,   // the number of bytes in the last second
    freq_g: f64, // the gradient,
    t: SimTime,  // time of the last calc

    debug: OutVec,
    debug_p: OutVec,
    debug_g: OutVec,
}
impl Module for Connector {
    fn new() -> Self {
        Self {
            freq: 0.0,
            freq_g: 0.0,
            t: SimTime::ZERO,
            debug_p: OutVec::new("drop".to_string(), Some(module_path())),
            debug: OutVec::new("traffic".to_string(), Some(module_path())),
            debug_g: OutVec::new("traffic_g".to_string(), Some(module_path())),
        }
    }

    fn handle_message(&mut self, msg: Message) {
        let dur = (SimTime::now() - self.t).as_secs_f64();
        if dur > 1.0 {
            self.freq = msg.header().length as f64;
            self.t = SimTime::now();
            self.debug.collect(self.freq);
        } else {
            let rem = (1.0 - dur) * self.freq + dur * self.freq_g * 0.01;
            let n_freq = rem + msg.header().length as f64;
            self.freq_g = n_freq - self.freq;
            self.freq = n_freq;
            self.t = SimTime::now();

            self.debug.collect(self.freq);
            self.debug_g.collect(self.freq_g);
        }

        let prob = (self.freq / 100_000.0).min(1.0) * msg.header().length as f64 / 2000.0;
        self.debug_p.collect(prob);

        match msg.header().last_gate.as_ref().map(|g| g.pos()) {
            Some(0) => send(msg, ("out", 0)),
            Some(1) => send(msg, ("out", 1)),
            _ => unreachable!(),
        }
    }

    fn at_sim_end(&mut self) {
        self.debug.finish();
        self.debug_g.finish();
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
        cfg.debug = true;
        cfg.cong_ctrl = true;
        set_tcp_cfg(cfg).unwrap();
        for k in 0..1 {
            self.handles.push(spawn(async move {
                let mut sock = TcpStream::connect("69.0.0.69:1000").await.unwrap();
                log::info!("[{k}] opening stream");
                let mut acc = 0;
                for i in 0..1 {
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

        let mut cfg = TcpConfig::default();
        cfg.debug = true;
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

fn main() {
    inet::init();

    Logger::new().set_logger();

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
