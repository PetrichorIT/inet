use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

use des::{prelude::*, registry, time::sleep};
use inet::{
    interface::{add_interface, Interface, NetworkDevice},
    UdpSocket,
};

#[derive(Default)]
struct Node {
    done: Arc<AtomicUsize>,
}

impl Module for Node {
    fn at_sim_start(&mut self, s: usize) {
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

        let done = self.done.clone();
        tokio::spawn(async move {
            if targets.is_empty() {
                done.fetch_add(1, Ordering::SeqCst);
                return;
            }

            let sock = UdpSocket::bind("0.0.0.0:0").await.unwrap();
            sock.set_broadcast(true).unwrap();
            for target in targets {
                sleep(Duration::from_secs_f64(random())).await;
                let buf = vec![42; target];
                tracing::info!("broadcasting {target} bytes");
                sock.send_to(&buf, "255.255.255.255:100").await.unwrap();
            }
            done.fetch_add(1, Ordering::SeqCst);
        });

        let done = self.done.clone();
        tokio::spawn(async move {
            if expected == 0 {
                done.fetch_add(1, Ordering::SeqCst);
                return;
            }

            let sock = UdpSocket::bind("0.0.0.0:100").await.unwrap();
            let mut acc = 0;
            while acc < expected {
                let mut buf = [0u8; 1024];
                let (n, from) = sock.recv_from(&mut buf).await.unwrap();
                tracing::info!("recieved {n} bytes from {}", from.ip());
                acc += n;
            }
            done.fetch_add(1, Ordering::SeqCst);
        });
    }

    fn num_sim_start_stages(&self) -> usize {
        2
    }

    fn at_sim_end(&mut self) {
        assert_eq!(self.done.load(Ordering::SeqCst), 2);
    }

    fn handle_message(&mut self, msg: Message) {
        panic!(
            "got unexepected message :: {} on module {}",
            msg.str(),
            current().name()
        );
    }
}

type Switch = inet::utils::LinkLayerSwitch;

#[derive(Default)]
struct Main;

impl Module for Main {
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

        tracing::info!("expecting: {:?}", targets);

        for i in 0..5 {
            let c = targets[i];
            let par = par_for("expected", &format!("node[{i}]"));
            par.set(c).unwrap();
        }
    }
}

#[test]
fn udp_broadcast() {
    let mut app = Sim::new(())
        .with_stack(inet::init)
        .with_ndl(
            "tests/udp-broadcast/main.ndl",
            registry![Node, Switch, Main],
        )
        .map_err(|e| println!("{e}"))
        .unwrap();
    app.include_par_file("tests/udp-broadcast/main.par")
        .unwrap();
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
