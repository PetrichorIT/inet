use des::{
    prelude::*,
    registry,
    tokio::{task::JoinHandle, time::sleep},
};
use inet::{
    interface::{add_interface, Interface, NetworkDevice},
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

        let target: String = par("targets").unwrap().into_inner();
        let targets = target
            .trim()
            .split(',')
            .filter(|s| !s.is_empty())
            .map(|v| v.trim().parse::<usize>().unwrap())
            .collect::<Vec<_>>();

        let expected: usize = par("expected").unwrap().parse().unwrap();

        self.handles.push(tokio::spawn(async move {
            if targets.is_empty() {
                return;
            }

            let sock = UdpSocket::bind("0.0.0.0:0").await.unwrap();
            sock.set_broadcast(true).unwrap();
            for target in targets {
                sleep(Duration::from_secs_f64(random())).await;
                let buf = vec![42; target];
                log::info!("broadcasting {target} bytes");
                sock.send_to(&buf, "255.255.255.255:100").await.unwrap();
            }
        }));

        self.handles.push(tokio::spawn(async move {
            if expected == 0 {
                return;
            }

            let sock = UdpSocket::bind("0.0.0.0:100").await.unwrap();
            let mut acc = 0;
            while acc < expected {
                let mut buf = [0u8; 1024];
                let (n, from) = sock.recv_from(&mut buf).await.unwrap();
                log::info!("recieved {n} bytes from {}", from.ip());
                acc += n;
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
        panic!(
            "got unexepected message :: {} on module {}",
            msg.str(),
            module_name()
        );
    }
}

type Switch = inet::utils::LinkLayerSwitch;

struct Main;
impl Module for Main {
    fn new() -> Main {
        Main
    }

    fn at_sim_start(&mut self, _stage: usize) {
        let mut targets = vec![0; 5];
        for i in 0..5 {
            let s = par_for("targets", &format!("node[{i}]"))
                .unwrap()
                .into_inner();
            for broadcast in s
                .trim()
                .split(',')
                .filter(|s| !s.is_empty())
                .map(|v| v.trim().parse::<usize>().unwrap())
            {
                for j in 0..5 {
                    if j == i {
                        continue;
                    }
                    targets[j] += broadcast;
                }
            }
        }

        log::info!("expecting: {:?}", targets);

        for i in 0..5 {
            let c = targets[i];
            let par = par_for("expected", &format!("node[{i}]"));
            par.set(c).unwrap();
        }
    }
}

#[test]
fn udp_broadcast() {
    inet::init();
    // Logger::new()
    // .interal_max_log_level(log::LevelFilter::Trace)
    // .set_logger();

    let app = NdlApplication::new(
        "tests/udp-broadcast/main.ndl",
        registry![Node, Switch, Main],
    )
    .map_err(|e| println!("{e}"))
    .unwrap();
    let mut app = NetworkApplication::new(app);
    app.include_par_file("tests/udp-broadcast/main.par");
    let rt = Runtime::new_with(app, RuntimeOptions::seeded(123));
    let _ = rt.run();
}

/*
Expected result:
⎡
⎢ Simulation ended
⎢  Ended at event #419 after 4.652457781s
⎣
*/
