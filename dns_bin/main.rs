use des::{prelude::*, registry};
use inet::{
    dns::*,
    interface::{add_interface, Interface, NetworkDevice},
    ip::{IpMask, Ipv4Packet},
};

/*
Concept
DNS0 = org
DNS1 = example
DNS2 = www
*/

// # CLIENT

struct Client {}
#[async_trait::async_trait]
impl AsyncModule for Client {
    fn new() -> Self {
        Self {}
    }

    async fn at_sim_start(&mut self, _stage: usize) {
        let ip = par("addr").unwrap().parse::<Ipv4Addr>().unwrap();
        add_interface(Interface::ethernet(
            &[ip.into()],
            NetworkDevice::eth_default(),
        ));
        add_interface(Interface::loopback());

        schedule_in(Message::new().kind(2334).build(), Duration::from_secs(10));

        tokio::spawn(async move {
            let mut server = DNSNameserver::new(
                DNSNodeInformation {
                    zone: DNSString::from(format!("{}", ip)),
                    domain_name: DNSString::new(""),
                    ip: IpAddr::V4(ip),
                },
                DNSSOAResourceRecord {
                    name: DNSString::new(""),
                    class: DNSClass::Internet,
                    ttl: 7000,
                    mname: DNSString::new(""),
                    rname: DNSString::new(""),
                    serial: 7000,
                    refresh: 7000,
                    retry: 7000,
                    expire: 7000,
                    minimum: 7000,
                },
            );

            server.allow_recursive_for(IpMask::catch_all_v4());
            server.launch().await.unwrap();
        });
    }

    async fn handle_message(&mut self, msg: Message) {
        let kind = msg.header().kind;
        match kind {
            2334 => {
                log::info!("[lookup]");
                let lookup = lookup_host("www.example.org:80").await;
                match lookup {
                    Ok(iter) => {
                        log::info!("[result]");
                        for addr in iter {
                            log::info!(">>> {}", addr)
                        }
                    }
                    Err(e) => log::error!(">>> {}", e),
                }
            }
            _ => {
                log::error!("{:?}", msg.content::<Ipv4Packet>());
                // let content = msg.cast::<Vec<u8>>().0;
                // let msg = DNSMessage::from_buffer(content).unwrap();
                // // log::info!("{:?}", msg)
                // for record in msg.response() {
                //     log::info!("> {}", record);
                // }
            }
        }
    }
}

struct DNSLocal {}
#[async_trait::async_trait]
impl AsyncModule for DNSLocal {
    fn new() -> Self {
        Self {}
    }

    async fn at_sim_start(&mut self, _: usize) {
        // let ip = par("addr").unwrap().parse::<Ipv4Addr>().unwrap();
        // add_interface(Interface::ethernet(
        //     &[ip.into()],
        //     NetworkDevice::eth_default(),
        // ));

        // tokio::spawn(async move {
        //     let mut server = DNSNameserver::new(
        //         DNSNodeInformation {
        //             zone: DNSString::from(format!("{}", ip)),
        //             domain_name: DNSString::new(""),
        //             ip: IpAddr::V4(ip),
        //         },
        //         DNSSOAResourceRecord {
        //             name: DNSString::new(""),
        //             class: DNSClass::Internet,
        //             ttl: 7000,
        //             mname: DNSString::new(""),
        //             rname: DNSString::new(""),
        //             serial: 7000,
        //             refresh: 7000,
        //             retry: 7000,
        //             expire: 7000,
        //             minimum: 7000,
        //         },
        //     );

        //     server.allow_recursive_for(IpMask::catch_all_v4());
        //     server.launch().await.unwrap();
        // });
    }
}

// # SERVER

struct DNSServer0 {
    server: Option<DNSNameserver>,
}
#[async_trait::async_trait]
impl AsyncModule for DNSServer0 {
    fn new() -> Self {
        Self {
            server: Some(
                DNSNameserver::from_zonefile("org", "dns_bin/zonefiles/", "ns0.namservers.org.")
                    .unwrap(),
            ),
        }
    }

    async fn at_sim_start(&mut self, _stage: usize) {
        let ip = par("addr").unwrap().parse::<Ipv4Addr>().unwrap();
        add_interface(Interface::ethernet(
            &[ip.into()],
            NetworkDevice::eth_default(),
        ));

        schedule_in(Message::new().kind(1111).build(), Duration::ZERO);
    }

    async fn handle_message(&mut self, msg: Message) {
        if msg.header().kind != 1111 {
            return;
        }
        let mut server = self.server.take().unwrap();
        tokio::spawn(async move {
            server.launch().await.unwrap();
        });
    }
}

struct DNSServer1 {
    server: Option<DNSNameserver>,
}
#[async_trait::async_trait]
impl AsyncModule for DNSServer1 {
    fn new() -> Self {
        Self {
            server: Some(
                DNSNameserver::from_zonefile(
                    "example.org.",
                    "dns_bin/zonefiles/",
                    if module_name() == "dns1" {
                        "ns1.example.org."
                    } else {
                        "ns2.example.org."
                    },
                )
                .unwrap(),
            ),
        }
    }

    async fn at_sim_start(&mut self, _stage: usize) {
        let ip = par("addr").unwrap().parse::<Ipv4Addr>().unwrap();
        add_interface(Interface::ethernet(
            &[ip.into()],
            NetworkDevice::eth_default(),
        ));

        schedule_in(Message::new().kind(1111).build(), Duration::ZERO);
    }

    async fn handle_message(&mut self, msg: Message) {
        if msg.header().kind != 1111 {
            return;
        }
        let mut server = self.server.take().unwrap();
        tokio::spawn(async move {
            server.launch().await.unwrap();
        });
    }
}

struct DNSServer2 {
    server: Option<DNSNameserver>,
}
#[async_trait::async_trait]
impl AsyncModule for DNSServer2 {
    fn new() -> Self {
        Self {
            server: Some(
                DNSNameserver::from_zonefile(".", "dns_bin/zonefiles/", "a.root-servers.net.")
                    .unwrap(),
            ),
        }
    }

    async fn at_sim_start(&mut self, _stage: usize) {
        let ip = par("addr").unwrap().parse::<Ipv4Addr>().unwrap();
        add_interface(Interface::ethernet(
            &[ip.into()],
            NetworkDevice::eth_default(),
        ));

        schedule_in(Message::new().kind(7912).build(), Duration::from_secs(5));
    }

    async fn handle_message(&mut self, msg: Message) {
        if msg.header().kind != 7912 {
            return;
        }
        let mut server = self.server.take().unwrap();
        tokio::spawn(async move {
            server.declare_root_ns();
            server.launch().await.unwrap();
        });
    }
}

const RMAP: [Ipv4Addr; 6] = [
    Ipv4Addr::new(200, 3, 43, 125),
    Ipv4Addr::new(100, 3, 43, 125),
    Ipv4Addr::new(100, 78, 43, 100),
    Ipv4Addr::new(100, 100, 100, 100),
    Ipv4Addr::new(100, 78, 43, 200),
    Ipv4Addr::new(192, 168, 2, 178),
];

struct Router {}
impl Module for Router {
    fn new() -> Self {
        Self {}
    }

    fn num_sim_start_stages(&self) -> usize {
        2
    }

    fn handle_message(&mut self, msg: Message) {
        if let Some(content) = msg.try_content::<Ipv4Packet>() {
            let Some((i, _)) = RMAP.iter().enumerate().find(|(_, &v)| v == content.dest) else {
                return
            };
            send(msg, ("out", i))
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

    let mut rt = NetworkRuntime::new(
        NdlApplication::new(
            "dns_bin/main.ndl",
            registry![Main, Router, DNSServer0, DNSServer1, DNSServer2, DNSLocal, Client],
        )
        .map_err(|e| println!("{e}"))
        .unwrap(),
    );
    rt.include_par_file("dns_bin/main.par");
    let rt = Runtime::new(rt);
    let _ = rt.run();
}
