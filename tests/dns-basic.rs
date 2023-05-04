use des::{prelude::*, registry};
use inet::{
    dns::*,
    interface::{add_interface, Interface, NetworkDevice},
    routing::{add_routing_entry, set_default_gateway},
};
use inet_types::ip::{IpMask, Ipv4Packet};

/*
Concept
DNS0 = org
DNS1 = example
DNS2 = www
*/

// # CLIENT

struct Client {
    suc: bool,
}
#[async_trait::async_trait]
impl AsyncModule for Client {
    fn new() -> Self {
        Self { suc: false }
    }

    async fn at_sim_start(&mut self, _stage: usize) {
        let ip = par("addr").unwrap().parse::<Ipv4Addr>().unwrap();
        add_interface(Interface::ethv4_named(
            "en0",
            NetworkDevice::eth(),
            ip,
            Ipv4Addr::new(255, 0, 0, 0),
        ))
        .unwrap();
        add_interface(Interface::loopback()).unwrap();
        set_default_gateway([ip.octets()[0], 0, 0, 1].into()).unwrap();

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
                        self.suc = true
                    }
                    Err(e) => panic!("{e}"),
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

    async fn at_sim_end(&mut self) {
        assert!(self.suc, "Did not finish succesfully")
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
                DNSNameserver::from_zonefile(
                    "org",
                    "tests/dns-basic/zonefiles/",
                    "ns0.namservers.org.",
                )
                .unwrap(),
            ),
        }
    }

    async fn at_sim_start(&mut self, _stage: usize) {
        let ip = par("addr").unwrap().parse::<Ipv4Addr>().unwrap();
        add_interface(Interface::ethv4_named(
            "en0",
            NetworkDevice::eth(),
            ip,
            Ipv4Addr::new(255, 0, 0, 0),
        ))
        .unwrap();
        set_default_gateway([ip.octets()[0], 0, 0, 1].into()).unwrap();

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
                    "tests/dns-basic/zonefiles/",
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
        add_interface(Interface::ethv4_named(
            "en0",
            NetworkDevice::eth(),
            ip,
            Ipv4Addr::new(255, 0, 0, 0),
        ))
        .unwrap();
        schedule_in(Message::new().kind(1111).build(), Duration::ZERO);
        set_default_gateway([ip.octets()[0], 0, 0, 1].into()).unwrap();
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
                DNSNameserver::from_zonefile(
                    ".",
                    "tests/dns-basic/zonefiles/",
                    "a.root-servers.net.",
                )
                .unwrap(),
            ),
        }
    }

    async fn at_sim_start(&mut self, _stage: usize) {
        let ip = par("addr").unwrap().parse::<Ipv4Addr>().unwrap();
        add_interface(Interface::ethv4_named(
            "en0",
            NetworkDevice::eth(),
            ip,
            Ipv4Addr::new(255, 0, 0, 0),
        ))
        .unwrap();
        set_default_gateway([ip.octets()[0], 0, 0, 1].into()).unwrap();

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

type Switch = inet::utils::LinkLayerSwitch;

struct Router;
impl Module for Router {
    fn new() -> Self {
        Router
    }

    fn at_sim_start(&mut self, _stage: usize) {
        let ip = par("addr").unwrap().parse().unwrap();
        add_interface(Interface::ethv4(
            NetworkDevice::eth_select(|p| p.input.name() == "lan_in"),
            ip,
        ))
        .unwrap();

        add_interface(Interface::ethv4_named(
            "wan0",
            NetworkDevice::eth_select(|p| p.input.name() == "wan_in"),
            ip,
            Ipv4Addr::UNSPECIFIED,
        ))
        .unwrap();

        let rev_net = Ipv4Addr::new(if ip.octets()[0] == 100 { 200 } else { 100 }, 0, 0, 0);
        let rev = Ipv4Addr::new(if ip.octets()[0] == 100 { 200 } else { 100 }, 0, 0, 1);
        add_routing_entry(rev_net, Ipv4Addr::new(255, 0, 0, 0), rev, "wan0").unwrap();
    }

    fn handle_message(&mut self, msg: Message) {
        log::debug!("{}", msg.str());
    }
}

struct Main;
impl Module for Main {
    fn new() -> Main {
        Main
    }
}

#[test]
fn dns_basic() {
    inet::init();

    // Logger::new()
    //     .interal_max_log_level(log::LevelFilter::Warn)
    //     .try_set_logger()
    //     .unwrap();

    let mut rt = NetworkApplication::new(
        NdlApplication::new(
            "tests/dns-basic/main.ndl",
            registry![Main, Switch, DNSServer0, DNSServer1, DNSServer2, Client, Router],
        )
        .map_err(|e| println!("{e}"))
        .unwrap(),
    );
    rt.include_par_file("tests/dns-basic/main.par");
    let rt = Runtime::new_with(rt, RuntimeOptions::seeded(123));
    let _ = rt.run();
}
