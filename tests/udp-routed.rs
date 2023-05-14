use des::{prelude::*, registry, time::sleep, tokio::task::JoinHandle};
use fxhash::{FxBuildHasher, FxHashMap};
use inet::{
    interface::{add_interface, Interface, NetworkDevice},
    routing::{add_routing_entry, set_default_gateway},
    UdpSocket,
};

struct Node {
    handles: Vec<JoinHandle<()>>,
}
#[async_trait::async_trait]
impl AsyncModule for Node {
    fn new() -> Self {
        Self {
            handles: Vec::new(),
        }
    }

    async fn at_sim_start(&mut self, s: usize) {
        if s == 0 {
            return;
        }

        let ip = par("addr").unwrap().parse().unwrap();
        add_interface(Interface::ethv4(NetworkDevice::eth(), ip)).unwrap();
        set_default_gateway([ip.octets()[0], 0, 0, 1]).unwrap();

        let target: String = par("targets").unwrap().into_inner();
        let targets = target
            .trim()
            .split(',')
            .filter(|s| !s.trim().is_empty())
            .map(|v| v.trim().parse::<Ipv4Addr>().unwrap())
            .collect::<Vec<_>>();

        self.handles.push(tokio::spawn(async move {
            if targets.is_empty() {
                return;
            }

            let sock = UdpSocket::bind("0.0.0.0:0").await.unwrap();
            for target in targets {
                sleep(Duration::from_secs_f64(random())).await;
                let buf = [42; 42];
                log::info!("sending 42 bytes to {target}");

                sock.send_to(&buf, SocketAddrV4::new(target, 100))
                    .await
                    .unwrap();
            }
        }));

        let expected: usize = par("expected").unwrap().parse().unwrap();
        self.handles.push(tokio::spawn(async move {
            if expected == 0 {
                return;
            }
            let sock = UdpSocket::bind("0.0.0.0:100").await.unwrap();
            for _ in 0..expected {
                let mut buf = [0u8; 1024];
                let (n, from) = sock.recv_from(&mut buf).await.unwrap();
                log::info!("recieved {n} bytes from {}", from.ip());
            }
        }));
    }

    fn num_sim_start_stages(&self) -> usize {
        2
    }

    async fn at_sim_end(&mut self) {
        for h in self.handles.drain(..) {
            h.await.unwrap();
        }
    }

    async fn handle_message(&mut self, msg: Message) {
        panic!("msg :: {} :: {}", msg.str(), module_name())
    }
}

type Switch = inet::utils::LinkLayerSwitch;

struct Router {}
impl Module for Router {
    fn new() -> Self {
        Router {}
    }

    fn at_sim_start(&mut self, _stage: usize) {
        let ip = par("addr").unwrap().parse().unwrap();
        add_interface(Interface::ethv4(
            NetworkDevice::eth_select(|p| p.input.name() == "lan_in"),
            ip,
        ))
        .unwrap();

        add_interface(Interface::ethv4_named(
            "wan0",
            NetworkDevice::eth_select(|p| p.input.name() == "wan_in"),
            ip,
            Ipv4Addr::UNSPECIFIED,
        ))
        .unwrap();

        let rev_net = Ipv4Addr::new(if ip.octets()[0] == 100 { 200 } else { 100 }, 0, 0, 0);
        let rev = Ipv4Addr::new(if ip.octets()[0] == 100 { 200 } else { 100 }, 0, 0, 1);
        add_routing_entry(rev_net, Ipv4Addr::new(255, 255, 255, 0), rev, "wan0").unwrap();
    }

    fn handle_message(&mut self, msg: Message) {
        log::debug!("{}", msg.str());
    }
}

struct Main;
impl Module for Main {
    fn new() -> Main {
        Main
    }

    fn at_sim_start(&mut self, _stage: usize) {
        let mut targets = FxHashMap::with_hasher(FxBuildHasher::default());

        for side in ["left", "right"] {
            for i in 0..5 {
                let s = par_for("targets", &format!("{side}[{i}]"))
                    .unwrap()
                    .into_inner();
                if s.trim().is_empty() {
                    continue;
                }

                for s in s.split(',') {
                    if s.trim().is_empty() {
                        continue;
                    }
                    let s = s.trim().parse::<Ipv4Addr>().unwrap();
                    *targets.entry(s).or_insert(0) += 1;
                }
            }
        }

        log::info!("expecting {targets:?}");

        for (side, prefix) in [("left", 100), ("right", 200)] {
            for i in 0..5 {
                let ip = Ipv4Addr::new(prefix, 0, 0, 100 + i);
                par_for("expected", &format!("{side}[{i}]"))
                    .set(targets.get(&ip).unwrap_or(&0))
                    .unwrap();
            }
        }
    }
}

#[test]
fn udp_routed() {
    inet::init();
    // Logger::new()
    // .interal_max_log_level(log::LevelFilter::Trace)
    // .set_logger();

    let app = NdlApplication::new(
        "tests/udp-routed/main.ndl",
        registry![Node, Switch, Main, Router],
    )
    .map_err(|e| println!("{e}"))
    .unwrap();
    let mut app = NetworkApplication::new(app);
    app.include_par_file("tests/udp-routed/main.par");
    let rt = Runtime::new_with(app, RuntimeOptions::seeded(123));
    let _ = rt.run();
}
