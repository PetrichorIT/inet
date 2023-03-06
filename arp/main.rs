use des::{
    prelude::*,
    registry,
    tokio::{spawn, time::sleep},
};
use inet::{
    debug,
    interface2::{add_interface2, Interface, NetworkDevice},
    ip::{IpPacket, Ipv4Flags, Ipv4Packet},
};

type Switch = inet::utils::LinkLayerSwitch;

struct Node {
    ip: Ipv4Addr,
}
#[async_trait::async_trait]
impl AsyncModule for Node {
    fn new() -> Self {
        Self {
            ip: Ipv4Addr::UNSPECIFIED,
        }
    }

    async fn at_sim_start(&mut self, _stage: usize) {
        let ip = par("addr").unwrap().parse().unwrap();
        add_interface2(Interface::ethv4(NetworkDevice::eth_default(), ip)).unwrap();

        self.ip = ip;

        spawn(async move {
            loop {
                sleep(Duration::from_secs_f64(random())).await;

                let target = Ipv4Addr::new(100, 0, 0, (random::<u8>() % 5) + 100);
                if target == ip {
                    continue;
                }

                log::info!("sending packet to {}", target);
                debug::send_ip(IpPacket::V4(Ipv4Packet {
                    dscp: 0,
                    enc: 0,
                    identification: 0,
                    flags: Ipv4Flags {
                        df: false,
                        mf: false,
                    },
                    fragment_offset: 0,
                    ttl: 255,
                    proto: 0,
                    src: ip,
                    dest: target,
                    content: vec![42; 42],
                }))
                .unwrap();

                break;
            }
        });
    }

    async fn handle_message(&mut self, msg: Message) {
        let msg = msg.content::<Ipv4Packet>();
        assert_eq!(msg.dest, self.ip);
        log::info!("received message from {}", msg.src);
    }
}

struct Main;
impl Module for Main {
    fn new() -> Self {
        Self
    }
}

fn main() {
    inet::init();
    Logger::new().set_logger();

    let mut app = NetworkRuntime::new(
        NdlApplication::new("arp/main.ndl", registry![Node, Switch, Main])
            .map_err(|e| println!("{e}"))
            .unwrap(),
    );
    app.include_par_file("arp/main.par");

    let rt = Runtime::new_with(app, RuntimeOptions::seeded(123).max_itr(200));
    let _ = rt.run().unwrap();
}
