use std::sync::{atomic::AtomicUsize, Arc};

use des::{prelude::*, registry};
use inet::{
    interface::{add_interface, Interface, NetworkDevice},
    tcp::{set_tcp_cfg, TcpConfig},
    TcpListener, TcpStream,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    spawn,
    task::JoinHandle,
};

struct Connector {
    freq: f64,  // the number of bytes in the last second
    t: SimTime, // time of the last calc

    drops: Arc<AtomicUsize>,
}

impl Default for Connector {
    fn default() -> Self {
        Self {
            freq: 0.0,
            t: SimTime::ZERO,
            drops: Arc::new(AtomicUsize::new(0)),
        }
    }
}

impl Module for Connector {
    fn at_sim_start(&mut self, _: usize) {
        // let drops = self.drops.clone();
        // spawn(async move {
        //     let mut recorder = OutVec::new("drops_per_sec".to_string(), Some(module_path()));
        //     for _i in 0..50 {
        //         sleep(Duration::from_secs(1)).await;
        //         let v = drops.swap(0, std::sync::atomic::Ordering::SeqCst);
        //         recorder.collect(v as f64);
        //     }
        //     recorder.finish();
        // });
    }

    fn handle_message(&mut self, msg: Message) {
        let dur = (SimTime::now() - self.t).as_secs_f64();
        if dur > 1.0 {
            self.freq = msg.header().length as f64;
            self.t = SimTime::now();
            // self.debug.collect(self.freq);
        } else {
            let rem = (1.0 - dur) * self.freq;
            let n_freq = rem + msg.header().length as f64;
            self.freq = n_freq;
            self.t = SimTime::now();

            // self.debug.collect(self.freq);
        }

        let prob = (self.freq / 400_000.0).min(1.0) * msg.header().length as f64 / 2000.0;
        let prob = prob.powi(5).min(1.0);
        // self.debug_p.collect(prob);
        let distr = rand::distributions::Bernoulli::new(prob).unwrap();
        if sample(distr) {
            tracing::error!("### droping packet {}", msg.str());
            self.drops.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            return;
        }

        match msg.header().last_gate.as_ref().map(|g| g.pos()) {
            Some(0) => send(msg, ("out", 0)),
            Some(1) => send(msg, ("out", 1)),
            _ => unreachable!(),
        }
    }

    fn at_sim_end(&mut self) {
        // self.debug.finish();
        // self.debug_p.finish();
    }
}

#[derive(Default)]
struct Client {
    handles: Vec<JoinHandle<()>>,
}

impl Module for Client {
    fn at_sim_start(&mut self, _: usize) {
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
                tracing::info!("[{k}] opening stream");
                let mut acc = 0;
                for i in 0..1000 {
                    let n = (random::<usize>() % 2000) + 1000;
                    let x = ((i ^ n) & 0xff) as u8;
                    acc += n;
                    tracing::info!("[{k}] sending new byte stack [{x:x}; {n}]");
                    sock.write_all(&vec![x; n]).await.unwrap();
                    // sleep(Duration::from_secs_f64(0.025 * random::<f64>())).await;
                }
                tracing::info!("[{k}] closing client after {acc} bytes");
                println!("closing client");
                drop(sock);
            }));
        }
    }
}

#[derive(Default)]
struct Server {}

impl Module for Server {
    fn at_sim_start(&mut self, _: usize) {
        add_interface(Interface::ethv4(
            NetworkDevice::eth(),
            Ipv4Addr::new(69, 0, 0, 69),
        ))
        .unwrap();

        let mut cfg = TcpConfig::default();
        // cfg.debug = true;
        cfg.cong_ctrl = true;
        set_tcp_cfg(cfg).unwrap();

        spawn(async move {
            let list = TcpListener::bind((Ipv4Addr::UNSPECIFIED, 1000))
                .await
                .unwrap();
            loop {
                let (mut stream, from) = list.accept().await.unwrap();
                spawn(async move {
                    tracing::info!("got incoming connection from {from:?}");
                    let mut acc = 0;
                    loop {
                        let mut buf = [0; 1024];
                        let n = stream.read(&mut buf).await.unwrap();
                        acc += n;
                        tracing::info!("recevied {n} additional bytes for a total of {acc}");
                        if n == 0 {
                            break;
                        }
                    }
                    tracing::info!("dropping server side stream from {from:?}");
                    println!(
                        "dropping server side stream from {from:?} after {} bytes",
                        acc
                    );
                });
            }
        });
    }
}

fn main() {
    // des::tracing::Subscriber::default().init().unwrap();
    // Logger::new().policy(Policy).set_logger();

    let mut app = Sim::new(())
        .with_stack(inet::init)
        .with_ndl(
            "inet/src/bin/tcp.ndl",
            registry![Client, Server, Connector, else _],
        )
        .map_err(|e| println!("{e}"))
        .unwrap();

    app.include_par_file("inet/src/bin/tcp.par").unwrap();

    let rt = Builder::seeded(123).build(app);
    let _ = rt.run().unwrap();
}
