use des::{net::hooks::*, prelude::*, tokio::net::IOContext};
use inet::{dns::*, FromBytestreamDepc, IntoBytestreamDepc};
use std::str::FromStr;

/*
Concept
DNS0 = org
DNS1 = example
DNS2 = www



*/

#[NdlModule("bin")]
struct Client {}
#[async_trait::async_trait]
impl AsyncModule for Client {
    fn new() -> Self {
        Self {}
    }

    async fn at_sim_start(&mut self, _stage: usize) {
        let ip = par("addr").unwrap().parse::<Ipv4Addr>().unwrap();
        IOContext::new(random(), ip).set();

        schedule_in(Message::new().kind(2334).build(), Duration::from_secs(10));
    }

    async fn handle_message(&mut self, msg: Message) {
        match msg.header().kind {
            2334 => {
                let msg = DNSMessage::question_aaaa(7523, "www.example.org.");

                let mut buf = Vec::new();
                msg.into_bytestream(&mut buf).unwrap();
                // println!("{:?}", buf);
                send(
                    Message::new()
                        .src_node(tokio::net::get_ip().unwrap())
                        .dest_node(IpAddr::V4(Ipv4Addr::from_str("100.3.43.125").unwrap()))
                        .content(buf)
                        .build(),
                    "out",
                )
            }
            _ => {
                let content = msg.cast::<Vec<u8>>().0;
                let msg = DNSMessage::from_bytestream(content).unwrap();
                // log::info!("{:?}", msg)
                for record in msg.response() {
                    log::info!("> {}", record);
                }
            }
        }
    }
}

#[NdlModule("bin")]
struct DNSServer0 {
    server: DNSNameserver,
}
#[async_trait::async_trait]
impl AsyncModule for DNSServer0 {
    fn new() -> Self {
        Self {
            server: DNSNameserver::new(
                DNSSOAResourceRecord {
                    name: "org.".into(),
                    class: DNSClass::Internet,
                    ttl: 6086,
                    mname: "ns1.org.".into(),
                    rname: "org@mail.com.".into(),
                    serial: 100,
                    refresh: 6086,
                    retry: 6086,
                    expire: 6086,
                    minimum: 6086,
                },
                DNSNSResourceRecord {
                    name: "org.".into(),
                    ttl: 6086,
                    class: DNSClass::Internet,
                    ns: Vec::new(),
                },
            ),
        }
    }

    async fn at_sim_start(&mut self, _stage: usize) {
        let ip = par("addr").unwrap().parse::<Ipv4Addr>().unwrap();
        IOContext::new(random(), ip).set();

        self.server
            .add_ns_entry("example.", "ns1.example.org", None, None);
        self.server.add_address_entry(
            "ns1.example.org",
            IpAddr::V4(Ipv4Addr::new(100, 78, 43, 100)),
            None,
            None,
        );
        self.server.add_address_entry(
            "ns1.example.org",
            IpAddr::V6(Ipv6Addr::from(random::<[u8; 16]>())),
            None,
            None,
        );

        self.server
            .add_ns_entry("example.", "ns2.example.org", None, None);
        self.server.add_address_entry(
            "ns2.example.org",
            IpAddr::V4(Ipv4Addr::new(100, 78, 43, 200)),
            None,
            None,
        );
    }

    async fn handle_message(&mut self, msg: Message) {
        if let Ok((content, header)) = msg.try_cast::<Vec<u8>>() {
            let msg = DNSMessage::from_bytestream(content).unwrap();
            let resp = self.server.handle(msg);
            let Some(resp) = resp else { return };

            let mut encoded = Vec::new();
            resp.into_bytestream(&mut encoded).unwrap();

            send(
                Message::new()
                    .src_node(tokio::net::get_ip().unwrap())
                    .dest_node(header.src_addr.ip())
                    .content(encoded)
                    .build(),
                "out",
            )
        }
    }
}

#[NdlModule("bin")]
struct DNSServer1 {
    server: DNSNameserver,
}
#[async_trait::async_trait]
impl AsyncModule for DNSServer1 {
    fn new() -> Self {
        Self {
            server: DNSNameserver::new(
                DNSSOAResourceRecord {
                    name: "example.org.".into(),
                    class: DNSClass::Internet,
                    ttl: 6086,
                    mname: "ns1.example.org.".into(),
                    rname: "example.org@mail.com.".into(),
                    serial: 100,
                    refresh: 6086,
                    retry: 6086,
                    expire: 6086,
                    minimum: 6086,
                },
                DNSNSResourceRecord {
                    name: "example.org.".into(),
                    ttl: 6086,
                    class: DNSClass::Internet,
                    ns: Vec::new(),
                },
            ),
        }
    }

    async fn at_sim_start(&mut self, _stage: usize) {
        let ip = par("addr").unwrap().parse::<Ipv4Addr>().unwrap();
        IOContext::new(random(), ip).set();

        self.server.add_address_entry(
            "www.example.org.",
            IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)),
            None,
            None,
        );

        self.server.add_address_entry(
            "www.example.org.",
            IpAddr::V6(Ipv6Addr::from(random::<[u8; 16]>())),
            None,
            None,
        );
    }
}

#[NdlModule("bin")]
struct DNSServer2 {}
#[async_trait::async_trait]
impl AsyncModule for DNSServer2 {
    fn new() -> Self {
        Self {}
    }

    async fn at_sim_start(&mut self, _stage: usize) {
        let ip = par("addr").unwrap().parse::<Ipv4Addr>().unwrap();
        IOContext::new(random(), ip).set();
    }
}

#[NdlModule("bin")]
struct Router {}
impl Module for Router {
    fn new() -> Self {
        Self {}
    }

    fn num_sim_start_stages(&self) -> usize {
        2
    }

    fn at_sim_start(&mut self, stage: usize) {
        if stage == 1 {
            IOContext::new(random(), Ipv4Addr::new(1, 1, 1, 1)).set();
            let _ = create_hook(RoutingHook::new(RoutingHookOptions::INET), 0);
        }
    }

    fn handle_message(&mut self, _msg: Message) {}
}

#[NdlSubsystem("bin")]
struct Main {}

fn main() {
    ScopedLogger::new().finish().unwrap();

    let rt = Main {}.build_rt();
    let rt = Runtime::new(rt);
    let _ = rt.run();
}
