use des::{prelude::*, registry, time::sleep};
use inet::{
    arp::arpa,
    interface::{add_interface, Interface, NetworkDevice},
    UdpSocket,
};
use inet_types::ip::Ipv6Packet;
use tokio::task::JoinHandle;

struct Node {
    handles: Vec<JoinHandle<()>>,
}

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
        add_interface(Interface::eth(NetworkDevice::eth(), ip)).unwrap();

        let target: String = par("targets").unwrap().into_inner();
        let targets = target
            .trim()
            .split(',')
            .filter(|s| !s.is_empty())
            .map(|v| {
                Ipv6Addr::from([
                    0xfe,
                    0x80,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0xaa,
                    v.parse::<u8>().unwrap(),
                ])
            })
            .collect::<Vec<_>>();

        let expected: usize = par("expected").unwrap().parse().unwrap();

        self.handles.push(tokio::spawn(async move {
            let sock = UdpSocket::bind(":::0").await.unwrap();
            for target in targets {
                sleep(Duration::from_secs_f64(random())).await;
                let buf = [42; 42];
                tracing::info!("sending 42 bytes to {target}");
                sock.send_to(&buf, SocketAddrV6::new(target, 100, 0, 0))
                    .await
                    .unwrap();
            }
        }));

        self.handles.push(tokio::spawn(async move {
            let sock = UdpSocket::bind(":::100").await.unwrap();
            for _ in 0..expected {
                let mut buf = [0u8; 1024];
                let (n, from) = sock.recv_from(&mut buf).await.unwrap();
                tracing::info!("recieved {n} bytes from {}", from.ip());
            }
        }));
    }

    fn num_sim_start_stages(&self) -> usize {
        2
    }

    async fn at_sim_end(&mut self) {
        for entry in arpa().unwrap() {
            tracing::debug!("{entry}")
        }
        for h in self.handles.drain(..) {
            h.await.unwrap();
        }
    }

    async fn handle_message(&mut self, msg: Message) {
        tracing::error!(
            "msg :: {} :: {} // {:?} -> {:?}",
            msg.str(),
            current().name(),
            msg.content::<Ipv6Packet>().src,
            msg.content::<Ipv6Packet>().dest
        );
        panic!()
    }
}

type Switch = inet::utils::LinkLayerSwitch;

struct Main;
impl Module for Main {
    fn new() -> Main {
        Main
    }

    fn at_sim_start(&mut self, _stage: usize) {
        let mut targets = Vec::new();
        for i in 0..5 {
            let s = par_for("targets", &format!("node[{i}]"))
                .unwrap()
                .into_inner();
            targets.extend(
                s.trim()
                    .split(',')
                    .filter(|s| !s.is_empty())
                    .map(|v| v.parse::<u8>().unwrap()),
            )
        }

        for i in 0..5 {
            let c = targets.iter().filter(|e| **e == i).count();
            let par = par_for("expected", &format!("node[{i}]"));
            par.set(c).unwrap();
        }
    }
}

#[test]
fn udp_lan_v6() {
    inet::init();
    // Logger::new()
    // .interal_max_log_level(tracing::LevelFilter::Trace)
    // .set_logger();

    let app = NdlApplication::new("tests/udp-lan/main.ndl", registry![Node, Switch, Main])
        .map_err(|e| println!("{e}"))
        .unwrap();
    let mut app = NetworkApplication::new(app);
    app.include_par_file("tests/udp-lan/v6.par");
    let rt = Builder::seeded(123).build(app);
    let _ = rt.run();
}

/*
Expected result:
⎡
⎢ Simulation ended
⎢  Ended at event #419 after 4.652457781s
⎣
*/
