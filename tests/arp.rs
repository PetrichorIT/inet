use des::{prelude::*, registry, time::sleep, tokio::spawn};
use inet::{
    arp::arpa,
    debug,
    interface::{add_interface, Interface, NetworkDevice},
};
use inet_types::ip::{IpPacket, Ipv4Packet, Ipv6Packet};
use serial_test::serial;

type Switch = inet::utils::LinkLayerSwitch;

struct Node {
    ip: IpAddr,
}
#[async_trait::async_trait]
impl AsyncModule for Node {
    fn new() -> Self {
        Self {
            ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        }
    }

    async fn at_sim_start(&mut self, _stage: usize) {
        let ip = par("addr").unwrap().parse().unwrap();
        add_interface(Interface::eth(NetworkDevice::eth(), ip)).unwrap();

        self.ip = ip;

        let mut valid_addrs = Vec::with_capacity(5);
        for i in 0..5 {
            let ip: IpAddr = par_for("addr", &format!("node[{i}]"))
                .unwrap()
                .parse()
                .unwrap();
            valid_addrs.push(ip)
        }

        spawn(async move {
            loop {
                sleep(Duration::from_secs_f64(random())).await;

                let target = valid_addrs[random::<usize>() % 5];
                if target == ip {
                    continue;
                }

                log::info!("sending packet to {}", target);
                debug::send_ip(IpPacket::new(ip, target, vec![42, 42])).unwrap();
            }
        });
    }

    async fn handle_message(&mut self, msg: Message) {
        if msg.can_cast::<Ipv4Packet>() {
            let msg = msg.content::<Ipv4Packet>();
            assert_eq!(msg.dest, self.ip);
            log::info!("received message from {}", msg.src);
        }

        if msg.can_cast::<Ipv6Packet>() {
            let msg = msg.content::<Ipv6Packet>();
            assert_eq!(msg.dest, self.ip);
            log::info!("received message from {}", msg.src);
        }
    }

    async fn at_sim_end(&mut self) {
        let r = arpa().unwrap();
        assert_eq!(r.len(), 6);
    }
}

struct Main;
impl Module for Main {
    fn new() -> Self {
        Self
    }
}

#[test]
#[serial]
fn v4() {
    inet::init();
    // Logger::new().set_logger();

    let mut app = NetworkApplication::new(
        NdlApplication::new("tests/arp/main.ndl", registry![Node, Switch, Main])
            .map_err(|e| println!("{e}"))
            .unwrap(),
    );
    app.include_par_file("tests/arp/v4.par");

    let rt = Runtime::new_with(app, RuntimeOptions::seeded(123).max_itr(500));
    let _ = rt.run().unwrap_premature_abort();
}

#[test]
#[serial]
fn v6() {
    inet::init();
    // Logger::new().set_logger();

    let mut app = NetworkApplication::new(
        NdlApplication::new("tests/arp/main.ndl", registry![Node, Switch, Main])
            .map_err(|e| println!("{e}"))
            .unwrap(),
    );
    app.include_par_file("tests/arp/v6.par");

    let rt = Runtime::new_with(app, RuntimeOptions::seeded(123).max_itr(500));
    let _ = rt.run().unwrap_premature_abort();
}
