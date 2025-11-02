use des::{net::globals, prelude::*, registry, time::sleep};
use inet::{
    interface::{InterfaceDef, NetworkDevice},
    ioctx,
    ipv4::{arp::arpa, socket::RawV4Socket},
};
use serial_test::serial;
use tokio::spawn;
use types::ip::Ipv4Packet;

type Switch = inet::utils::LinkLayerSwitch;

struct Node {
    ip: Ipv4Addr,
}

impl Default for Node {
    fn default() -> Self {
        Self {
            ip: Ipv4Addr::UNSPECIFIED,
        }
    }
}

impl Module for Node {
    fn at_sim_start(&mut self, _stage: usize) {
        let ip = current().prop::<Ipv4Addr>("addr").unwrap().get().unwrap();
        ioctx()
            .add_interface(InterfaceDef::new("en0", NetworkDevice::eth()).ipv4(ip))
            .unwrap();

        self.ip = ip;

        let mut valid_addrs = Vec::with_capacity(5);
        for i in 0..5 {
            let ip = globals()
                .get(&format!("node[{i}]").into())
                .unwrap()
                .prop::<Ipv4Addr>("addr")
                .unwrap()
                .get()
                .unwrap();
            valid_addrs.push(ip)
        }

        spawn(async move {
            let mut sock = RawV4Socket::new(0).unwrap();

            let mut index = random::<u64>() as usize % 5;
            loop {
                sleep(Duration::from_secs_f64(random())).await;

                let target = valid_addrs[index];
                index = (index + 1) % 5;
                if target == ip {
                    continue;
                }

                tracing::info!("sending packet to {}", target);
                sock.bind((ip, 0)).await.unwrap();
                sock.try_send_to(&[42, 42], target).unwrap();
            }
        });
    }

    fn handle_message(&mut self, msg: Message) {
        if msg.body.is::<Ipv4Packet>() {
            let msg = msg.body.content::<Ipv4Packet>();
            assert_eq!(msg.dst, self.ip);
            tracing::info!("received message from {}", msg.src);
        }
    }

    fn at_sim_end(&mut self) -> Result<(), RuntimeError> {
        let r = arpa().unwrap();
        assert_eq!(r.len(), 6);
        Ok(())
    }
}

#[test]
#[serial]
fn v4() -> Result<(), RuntimeError> {
    let app = Sim::new(())
        .with_stack(inet::init)
        .with_cfg(include_str!("arp/v4.par.yml"))
        .with_ndl("tests/arp/main.yml", registry![Node, Switch, else _])
        .map_err(|e| println!("{e}"))
        .unwrap();
    let rt = Builder::seeded(123).max_itr(1000).build(app.freeze());
    rt.run().map(|_| ())
}
