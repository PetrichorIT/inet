use des::{
    net::plugin::add_plugin,
    prelude::*,
    registry,
    tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        spawn,
        task::JoinHandle,
        time::sleep,
    },
};
use inet::{
    interface::{add_interface, Interface, NetworkDevice},
    tcp::{set_tcp_cfg, TcpConfig, TcpDebugPlugin},
    TcpListener, TcpStream,
};

struct Connector {
    freq: f64,  // the number of bytes in the last second
    t: SimTime, // time of the last calc
    debug: OutVec,
}
impl Module for Connector {
    fn new() -> Self {
        Self {
            freq: 0.0,
            t: SimTime::ZERO,
            debug: OutVec::new("traffic".to_string(), Some(module_path())),
        }
    }

    fn handle_message(&mut self, msg: Message) {
        let dur = (SimTime::now() - self.t).as_secs_f64();
        if dur > 1.0 {
            self.freq = msg.header().length as f64;
            self.t = SimTime::now();
            self.debug.collect(self.freq);
        } else {
            let rem = (1.0 - dur) * self.freq;
            self.freq = rem + msg.header().length as f64;
            self.t = SimTime::now();
            self.debug.collect(self.freq);
        }

        match msg.header().last_gate.as_ref().map(|g| g.pos()) {
            Some(0) => send(msg, ("out", 0)),
            Some(1) => send(msg, ("out", 1)),
            _ => unreachable!(),
        }
    }

    fn at_sim_end(&mut self) {
        self.debug.finish();
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

        self.handles.push(spawn(async move {
            let mut sock = TcpStream::connect("69.0.0.69:1000").await.unwrap();
            log::info!("opening stream");
            for i in 0..10 {
                let n = (random::<usize>() % 2000) + 1000;
                let x = ((i ^ n) & 0xff) as u8;
                log::info!("sending new byte stack [{x:x}; {n}]");
                sock.write_all(&vec![x; n]).await.unwrap();
                sleep(Duration::from_secs_f64(0.125 * random::<f64>())).await;
            }
            // sleep(Duration::from_secs(1)).await;
            drop(sock);
        }));
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

    let rt = Runtime::new_with(app, RuntimeOptions::seeded(123));
    let _ = rt.run().unwrap();
}
