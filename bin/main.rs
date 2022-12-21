use des::{net::globals, prelude::*};
use inet::{
    ip::*,
    routing::{BackwardRoutingDeamon, RandomRoutingDeamon, RoutingInformation},
    FromBytestream, IntoBytestream,
};

#[NdlModule("bin")]
struct Client {}

impl Module for Client {
    fn new() -> Self {
        Self {}
    }

    fn at_sim_start(&mut self, _stage: usize) {
        // if par("addr").unwrap().parse::<Ipv4Addr>().unwrap().octets()[0] == 50 {
        schedule_in(
            Message::new().kind(1111).build(),
            Duration::from_secs(random::<u64>() % 10),
        );
        // }
    }

    fn handle_message(&mut self, msg: Message) {
        let own = par("addr").unwrap().parse::<Ipv4Addr>().unwrap();
        match msg.header().kind {
            1111 => {
                let ip = [50, 100, 150, 200, 250][random::<usize>() % 5];
                let ip = Ipv4Addr::new(ip, ip, ip, ip);
                let pkt = IPPacket {
                    version: IPVersion::V4,
                    ihl: 0,
                    dscp: 0,
                    enc: 0,
                    len: 20 + 100,
                    flags: IPFlags {
                        df: false,
                        mf: false,
                    },
                    identification: 0,
                    ttl: 8,
                    fragment_offset: 0,
                    proto: 123,
                    checksum: 0,

                    src: own,
                    dest: ip,
                    content: vec![42; 100],
                };

                let content = pkt.into_buffer().unwrap();
                // println!("{:x?}", &content[..20]);
                log::info!("Sending packet from {} to {}", own, ip);

                send(Message::new().content(content).build(), "out");
                schedule_in(
                    Message::new().kind(1111).build(),
                    Duration::from_secs(1 + random::<u64>() % 5),
                );
            }
            _ => {
                let (content, _) = msg.cast::<Vec<u8>>();
                // println!("{:x?}", &content[..20]);
                let ip = IPPacket::from_buffer(content).unwrap();
                // println!("{}", ip.dest);
                if ip.dest == own {
                    log::info!("Received pkt from {} -> consumed", ip.src);
                } else {
                    log::info!("Received pkt from {} -> redirected", ip.src);
                    let content = ip.into_buffer().unwrap();
                    let msg = Message::new().content(content).build();
                    send(msg, "out")
                }
            }
        }
    }
}

#[NdlModule("bin")]
struct Router {
    router: Box<dyn inet::routing::Router>,
}

impl Module for Router {
    fn new() -> Self {
        Self {
            router: Box::new(BackwardRoutingDeamon::new(RandomRoutingDeamon::new())),
        }
    }

    fn at_sim_start(&mut self, _stage: usize) {
        let rinfo = RoutingInformation::collect();
        // log::info!("{:?}", rinfo);
        self.router.initalize(rinfo);
    }

    fn handle_message(&mut self, msg: Message) {
        if self.router.accepts(&msg) {
            self.router.route(msg).unwrap();
        }
    }

    fn at_sim_end(&mut self) {
        let topo = globals().topology.borrow().clone();
        topo.write_to_svg("topo.svg").unwrap()
    }
}

#[NdlSubsystem("bin")]
struct Main {}

fn main() {
    ScopedLogger::new()
        .interal_max_log_level(log::LevelFilter::Warn)
        .finish()
        .unwrap();
    let rt = Main {}.build_rt();
    let rt = Runtime::new_with(
        rt,
        RuntimeOptions::seeded(123).max_time(SimTime::from_duration(Duration::from_secs(1000))),
    );
    let _ = rt.run();
}
