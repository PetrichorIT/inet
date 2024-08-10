use std::{
    iter::repeat,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};

use des::{prelude::*, registry, time::sleep};
use inet::{
    arp::arpa,
    interface::{add_interface, Interface, NetworkDevice},
    UdpSocket,
};
use inet_types::ip::Ipv6Packet;

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

        let done = self.done.clone();
        tokio::spawn(async move {
            let sock = UdpSocket::bind(":::0").await.unwrap();
            for (i, target) in targets.into_iter().enumerate() {
                sleep(Duration::from_secs_f64(random())).await;
                let buf = repeat(42).take(100 + i).collect::<Vec<_>>();
                tracing::info!("sending {} bytes to {target}", buf.len());
                sock.send_to(&buf, SocketAddrV6::new(target, 100, 0, 0))
                    .await
                    .unwrap();
            }
            tracing::info!("done(send)");
            done.fetch_add(1, Ordering::SeqCst);
        });

        let done = self.done.clone();
        tokio::spawn(async move {
            let sock = UdpSocket::bind(":::100").await.unwrap();
            for _ in 0..expected {
                let mut buf = [0u8; 1024];
                let (n, from) = sock.recv_from(&mut buf).await.unwrap();
                tracing::info!("recieved {n} bytes from {}", from.ip());
            }
            tracing::info!("done(recv)");
            done.fetch_add(1, Ordering::SeqCst)
        });
    }

    fn num_sim_start_stages(&self) -> usize {
        2
    }

    fn at_sim_end(&mut self) {
        for entry in arpa().unwrap() {
            tracing::debug!("{entry}")
        }
        assert_eq!(
            self.done.load(Ordering::SeqCst),
            2,
            "Failed to join tasks: {}",
            current().name()
        );
    }

    fn handle_message(&mut self, msg: Message) {
        tracing::error!(
            "msg :: {} :: {} // {:?} -> {:?}",
            msg.str(),
            current().name(),
            msg.content::<Ipv6Packet>().src,
            msg.content::<Ipv6Packet>().dst
        );
        panic!()
    }
}

type Switch = inet::utils::LinkLayerSwitch;

#[derive(Default)]
struct Main;

impl Module for Main {
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
    let mut app = Sim::new(())
        .with_stack(inet::init)
        .with_ndl("tests/udp-lan/main.ndl", registry![Node, Switch, Main])
        .map_err(|e| println!("{e}"))
        .unwrap();
    app.include_par_file("tests/udp-lan/v6.par").unwrap();
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
