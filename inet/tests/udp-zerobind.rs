use des::{prelude::*, registry, time::sleep};
use inet::{
    interface::{add_interface, Interface, NetworkDevice},
    UdpSocket,
};
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
        add_interface(Interface::ethv4(NetworkDevice::eth(), ip)).unwrap();
        add_interface(Interface::loopback()).unwrap();

        let target: String = par("targets").unwrap().into_inner();
        let targets = target
            .trim()
            .split(',')
            .filter(|s| !s.is_empty())
            .map(|v| Ipv4Addr::new(100, 0, 0, v.parse::<u8>().unwrap() + 100))
            .collect::<Vec<_>>();

        let expected: usize = par("expected").unwrap().parse().unwrap();

        self.handles.push(tokio::spawn(async move {
            if targets.is_empty() {
                return;
            }
            let sock = UdpSocket::bind((ip, 0)).await.unwrap();
            let loopback = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
            for (i, target) in targets.into_iter().enumerate() {
                sleep(Duration::from_secs_f64(random())).await;
                let buf = vec![i as u8; 42];

                if target == ip {
                    tracing::info!("sending 42 bytes to 127.0.0.1:100");
                    loopback
                        .send_to(&buf, SocketAddrV4::new(Ipv4Addr::LOCALHOST, 100))
                        .await
                        .unwrap();
                } else {
                    tracing::info!("sending 42 bytes to {target}");
                    sock.send_to(&buf, SocketAddrV4::new(target, 100))
                        .await
                        .unwrap();
                }
            }

            // tracing::debug!("<fin> sending");
        }));

        self.handles.push(tokio::spawn(async move {
            if expected == 0 {
                return;
            }
            let sock = UdpSocket::bind("0.0.0.0:100").await.unwrap();
            for _ in 0..expected {
                let mut buf = [0u8; 1024];
                let (n, from) = sock.recv_from(&mut buf).await.unwrap();
                tracing::info!("recieved {n}({}) bytes from {}", buf[0], from.ip());
            }

            // tracing::debug!("<fin> receiving");
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

    async fn handle_message(&mut self, _: Message) {
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

        tracing::info!("expecting {targets:?}");

        for i in 0..5 {
            let c = targets.iter().filter(|e| **e == i).count();
            let par = par_for("expected", &format!("node[{i}]"));
            par.set(c).unwrap();
        }
    }
}

#[test]
fn udp_zerobind() {
    inet::init();
    // Logger::new()
    // .interal_max_log_level(tracing::LevelFilter::Trace)
    // .set_logger();

    let app = NdlApplication::new("tests/udp-zerobind/main.ndl", registry![Node, Switch, Main])
        .map_err(|e| println!("{e}"))
        .unwrap();
    let mut app = NetworkApplication::new(app);
    app.include_par_file("tests/udp-zerobind/main.par");
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
