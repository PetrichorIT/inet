use des::{prelude::*, registry, time::sleep};
use inet::{
    arp::arpa,
    interface::{add_interface, Interface, NetworkDevice},
    socket::RawIpSocket,
};
use serial_test::serial;
use tokio::spawn;
use types::ip::{IpPacket, Ipv4Packet, Ipv6Packet};

type Switch = inet::utils::LinkLayerSwitch;

struct Node {
    ip: IpAddr,
}

impl Default for Node {
    fn default() -> Self {
        Self {
            ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        }
    }
}

impl Module for Node {
    fn at_sim_start(&mut self, _stage: usize) {
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
            let sock = if ip.is_ipv4() {
                RawIpSocket::new_v4().unwrap()
            } else {
                RawIpSocket::new_v6().unwrap()
            };

            let mut index = random::<usize>() % 5;
            loop {
                sleep(Duration::from_secs_f64(random())).await;

                let target = valid_addrs[index];
                index = (index + 1) % 5;
                if target == ip {
                    continue;
                }

                tracing::info!("sending packet to {}", target);
                sock.try_send(IpPacket::new(ip, target, vec![42, 42]))
                    .unwrap();
            }
        });
    }

    fn handle_message(&mut self, msg: Message) {
        if msg.can_cast::<Ipv4Packet>() {
            let msg = msg.content::<Ipv4Packet>();
            assert_eq!(msg.dst, self.ip);
            tracing::info!("received message from {}", msg.src);
        }

        if msg.can_cast::<Ipv6Packet>() {
            let msg = msg.content::<Ipv6Packet>();
            assert_eq!(msg.dst, self.ip);
            tracing::info!("received message from {}", msg.src);
        }
    }

    fn at_sim_end(&mut self) {
        let r = arpa().unwrap();
        assert_eq!(r.len(), 6);
    }
}

#[test]
#[serial]
fn v4() {
    let mut app = Sim::new(())
        .with_stack(inet::init)
        .with_ndl("tests/arp/main.yml", registry![Node, Switch, else _])
        .map_err(|e| println!("{e}"))
        .unwrap();
    app.include_par_file("tests/arp/v4.par.yml").unwrap();

    let rt = Builder::seeded(123).max_itr(1000).build(app);
    let _ = rt.run().unwrap_premature_abort();
}
