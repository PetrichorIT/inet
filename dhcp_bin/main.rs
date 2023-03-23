use std::collections::FxHashMap;

use des::{prelude::*, registry};
use inet::{
    dhcp::{DHCPClient, DHCPMessage, DHCPServer},
    IOContext,
};

struct Node {
    server: Option<DHCPServer>,
    client: Option<DHCPClient>,
}

impl Module for Node {
    fn new() -> Self {
        Self {
            server: None,
            client: None,
        }
    }

    fn at_sim_start(&mut self, _stage: usize) {
        let mac = random();

        if let Some(addr) = par("addr")
            .as_optional()
            .map(|s| s.parse::<Ipv4Addr>().unwrap())
        {
            IOContext::eth_with_addr(addr, mac).set();
            let subnet = par("subnet").unwrap().parse::<Ipv4Addr>().unwrap();
            let mut server = DHCPServer::new();
            let subnet = subnet.octets();

            server
                .subnet_mask(Ipv4Addr::new(255, 255, 255, 0))
                .dns(Ipv4Addr::new(192, 168, 2, 1))
                .router(Ipv4Addr::new(192, 168, 2, 1))
                .subnet_range(
                    Ipv4Addr::new(subnet[0], subnet[1], subnet[2], 100),
                    Ipv4Addr::new(subnet[0], subnet[1], subnet[2], 255),
                );

            send(Message::new().kind(1000).content(addr).build(), "out");

            self.server = Some(server);
            log::info!("Created server")
        } else {
            IOContext::eth_with_addr(Ipv4Addr::UNSPECIFIED, mac).set();
            self.client = Some(DHCPClient::new());
            log::info!("Created client");

            schedule_in(
                Message::new().kind(99).build(),
                Duration::from_secs_f64(random::<f64>() * 5.0),
            )
        }
    }

    fn handle_message(&mut self, msg: Message) {
        if msg.header().kind == 99 {
            self.client.as_mut().unwrap().start(None);
            return;
        }

        let ((from, to, msg), _) = msg.cast::<(SocketAddr, SocketAddr, DHCPMessage)>();
        if let Some(server) = &mut self.server {
            server.handle_message((from, to), msg);
            return;
        }

        if let Some(client) = &mut self.client {
            client.handle_message((from, to), msg);
            return;
        }
    }

    fn at_sim_end(&mut self) {
        if let Some(ref server) = self.server {
            println!("{:?}", server);
            return;
        }
    }
}

struct Switch {
    entries: FxHashMap<IpAddr, GateRef>,
    n: usize,
}

impl Module for Switch {
    fn new() -> Self {
        Self {
            entries: FxHashMap::new(),
            n: 0,
        }
    }

    fn at_sim_start(&mut self, _stage: usize) {
        let mut n = 0;
        loop {
            let Some(gate) = gate("out_ports", n) else {
                break;
            };

            if gate.path_end().is_none() {
                break;
            }
            n += 1
        }

        self.n = n;
    }

    fn handle_message(&mut self, msg: Message) {
        match msg.header().kind {
            1000 => {
                log::debug!(
                    "Added entry for {} at port {}",
                    *msg.content::<Ipv4Addr>(),
                    msg.header().last_gate.clone().unwrap().pos()
                );
                self.entries.insert(
                    IpAddr::V4(*msg.content::<Ipv4Addr>()),
                    gate("out_ports", msg.header().last_gate.clone().unwrap().pos()).unwrap(),
                );
            }
            _ => {
                let delay = Duration::from_secs_f64(random::<f64>() * 0.01);

                let (src, dest, _) = msg.content::<(SocketAddr, SocketAddr, DHCPMessage)>();
                if src.ip().is_unspecified() {
                    for i in 0..self.n {
                        send_in(
                            msg.dup::<(SocketAddr, SocketAddr, DHCPMessage)>(),
                            gate("out_ports", i).unwrap(),
                            delay,
                        )
                    }
                } else {
                    let path = self.entries.get(&dest.ip());
                    if let Some(path) = path {
                        send_in(msg, path, delay)
                    } else {
                        for i in 0..self.n {
                            send_in(
                                msg.dup::<(SocketAddr, SocketAddr, DHCPMessage)>(),
                                gate("out_ports", i).unwrap(),
                                delay,
                            )
                        }
                    }
                }
            }
        }
    }
}

struct Main;
impl Module for Main {
    fn new() -> Main {
        Main
    }
}

fn main() {
    inet::init();
    Logger::new()
        .interal_max_log_level(log::LevelFilter::Warn)
        .try_set_logger()
        .unwrap();
    let _ = Runtime::new_with(
        NetworkRuntime::new(
            NdlApplication::new("dhcp_bin/main.ndl", registry![Node, Main, Switch])
                .map_err(|e| println!("{e}"))
                .unwrap(),
        ),
        RuntimeOptions::seeded(123).include_env(),
    )
    .run();
}
