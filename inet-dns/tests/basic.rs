use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

use des::{prelude::*, registry};
use inet::{
    dns::lookup_host,
    interface::{add_interface, Interface, NetworkDevice},
    routing::{add_routing_entry, set_default_gateway},
};
use inet_dns::{types::*, DNSNameserver};
use inet_types::ip::{IpMask, Ipv4Packet};

/*
Concept
DNS0 = org
DNS1 = example
DNS2 = www
*/
// # CLIENT

#[derive(Default)]
struct Client {
    suc: Arc<AtomicBool>,
}

impl Module for Client {
    fn at_sim_start(&mut self, _stage: usize) {
        let ip = par("addr").unwrap().parse::<Ipv4Addr>().unwrap();
        add_interface(Interface::ethv4_named(
            "en0",
            NetworkDevice::eth(),
            ip,
            Ipv4Addr::new(255, 0, 0, 0),
        ))
        .unwrap();
        add_interface(Interface::loopback()).unwrap();
        set_default_gateway([ip.octets()[0], 0, 0, 1]).unwrap();

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

    fn handle_message(&mut self, msg: Message) {
        let suc = self.suc.clone();
        tokio::spawn(async move {
            let kind = msg.header().kind;
            match kind {
                2334 => {
                    tracing::info!("[lookup]");
                    let lookup = lookup_host("www.example.org:80").await;
                    match lookup {
                        Ok(iter) => {
                            tracing::info!("[result]");
                            for addr in iter {
                                tracing::info!(">>> {}", addr)
                            }
                            suc.store(true, Ordering::SeqCst);
                        }
                        Err(e) => panic!("{e}"),
                    }
                }
                _ => {
                    tracing::error!("{:?}", msg.content::<Ipv4Packet>());
                    // let content = msg.cast::<Vec<u8>>().0;
                    // let msg = DNSMessage::from_buffer(content).unwrap();
                    // // tracing::info!("{:?}", msg)
                    // for record in msg.response() {
                    //     tracing::info!("> {}", record);
                    // }
                }
            }
        });
    }

    fn at_sim_end(&mut self) {
        assert!(
            self.suc.load(Ordering::SeqCst),
            "Did not finish succesfully"
        )
    }
}

// # SERVER
#[derive(Default)]
struct DNSServer0;

impl Module for DNSServer0 {
    fn at_sim_start(&mut self, _stage: usize) {
        let ip = par("addr").unwrap().parse::<Ipv4Addr>().unwrap();
        add_interface(Interface::ethv4_named(
            "en0",
            NetworkDevice::eth(),
            ip,
            Ipv4Addr::new(255, 0, 0, 0),
        ))
        .unwrap();
        set_default_gateway([ip.octets()[0], 0, 0, 1]).unwrap();

        schedule_in(Message::new().kind(1111).build(), Duration::ZERO);
    }

    fn handle_message(&mut self, msg: Message) {
        if msg.header().kind != 1111 {
            return;
        }
        let mut server = DNSNameserver::from_zonefile(
            "org",
            "tests/dns-basic/zonefiles/",
            "ns0.nameservers.org.",
        )
        .unwrap();
        tokio::spawn(async move {
            server.launch().await.unwrap();
        });
    }
}

#[derive(Default)]
struct DNSServer1;

impl Module for DNSServer1 {
    fn at_sim_start(&mut self, _stage: usize) {
        let ip = par("addr").unwrap().parse::<Ipv4Addr>().unwrap();
        add_interface(Interface::ethv4_named(
            "en0",
            NetworkDevice::eth(),
            ip,
            Ipv4Addr::new(255, 0, 0, 0),
        ))
        .unwrap();
        schedule_in(Message::new().kind(1111).build(), Duration::ZERO);
        set_default_gateway([ip.octets()[0], 0, 0, 1]).unwrap();
    }

    fn handle_message(&mut self, msg: Message) {
        if msg.header().kind != 1111 {
            return;
        }
        let mut server = DNSNameserver::from_zonefile(
            "example.org.",
            "tests/dns-basic/zonefiles/",
            if current().name() == "dns1" {
                "ns1.example.org."
            } else {
                "ns2.example.org."
            },
        )
        .unwrap();
        tokio::spawn(async move {
            server.launch().await.unwrap();
        });
    }
}

#[derive(Default)]
struct DNSServer2;

impl Module for DNSServer2 {
    fn at_sim_start(&mut self, _stage: usize) {
        let ip = par("addr").unwrap().parse::<Ipv4Addr>().unwrap();
        add_interface(Interface::ethv4_named(
            "en0",
            NetworkDevice::eth(),
            ip,
            Ipv4Addr::new(255, 0, 0, 0),
        ))
        .unwrap();
        set_default_gateway([ip.octets()[0], 0, 0, 1]).unwrap();

        schedule_in(Message::new().kind(7912).build(), Duration::from_secs(5));
    }

    fn handle_message(&mut self, msg: Message) {
        if msg.header().kind != 7912 {
            return;
        }
        let mut server =
            DNSNameserver::from_zonefile(".", "tests/dns-basic/zonefiles/", "a.root-servers.net.")
                .unwrap();
        tokio::spawn(async move {
            server.declare_root_ns();
            server.launch().await.unwrap();
        });
    }
}

type Switch = inet::utils::LinkLayerSwitch;

#[derive(Default)]
struct Router;

impl Module for Router {
    fn at_sim_start(&mut self, _stage: usize) {
        let ip = par("addr").unwrap().parse().unwrap();
        add_interface(Interface::ethv4(NetworkDevice::bidirectional("lan"), ip)).unwrap();

        add_interface(Interface::ethv4_named(
            "wan0",
            NetworkDevice::bidirectional("wan"),
            ip,
            Ipv4Addr::new(255, 0, 0, 0),
        ))
        .unwrap();

        let rev_net = Ipv4Addr::new(if ip.octets()[0] == 100 { 200 } else { 100 }, 0, 0, 0);
        let rev = Ipv4Addr::new(if ip.octets()[0] == 100 { 200 } else { 100 }, 0, 0, 1);
        add_routing_entry(rev_net, Ipv4Addr::new(255, 0, 0, 0), rev, "wan0").unwrap();
    }

    fn handle_message(&mut self, msg: Message) {
        tracing::debug!("{}", msg.str());
    }
}

#[test]
fn dns_basic() {
    let mut rt = Sim::new(())
        .with_stack(inet::init)
        .with_ndl(
            "tests/dns-basic/main.yml",
            registry![Switch, DNSServer0, DNSServer1, DNSServer2, Client, Router, else _],
        )
        .map_err(|e| println!("{e}"))
        .unwrap();
    rt.include_par_file("tests/dns-basic/main.par.yml").unwrap();
    let rt = Builder::seeded(123).build(rt);
    let _ = rt.run();
}
