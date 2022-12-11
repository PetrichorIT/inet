use des::{net::hooks::*, prelude::*, tokio::net::IOContext};
use inet::{dns::*, FromBytestream};

/*
Concept
DNS0 = org
DNS1 = example
DNS2 = www



*/

#[NdlModule("bin")]
struct Client {
    resolver: DNSResolver,
}
#[async_trait::async_trait]
impl AsyncModule for Client {
    fn new() -> Self {
        Self {
            resolver: DNSResolver::new(),
        }
    }

    async fn at_sim_start(&mut self, _stage: usize) {
        let ip = par("addr").unwrap().parse::<Ipv4Addr>().unwrap();
        IOContext::new(random(), ip).set();

        schedule_in(Message::new().kind(2334).build(), Duration::from_secs(10));
    }

    async fn handle_message(&mut self, msg: Message) {
        let kind = msg.header().kind;
        match kind {
            2334 => {
                let lookup = self
                    .resolver
                    ._lookup_host("www.example.org")
                    .await
                    .solve_with_socket()
                    .await
                    .unwrap();
                // let lookup = self.resolver.lookup_host("www.example.org").await.unwrap();
                for ip in lookup {
                    log::info!(">>>>> {}", ip)
                }

                log::warn!("Staring second resolve");

                let lookup = self
                    .resolver
                    ._lookup_host("www.example.org")
                    .await
                    .solve_with_socket()
                    .await
                    .unwrap();

                for ip in lookup {
                    log::info!(">>>>> {}", ip)
                }

                // let msg = DNSMessage::question_a(7523, "www.example.org.");

                // let buf = msg.into_buffer().unwrap();
                // // println!("{:?}", buf);
                // send(
                //     Message::new()
                //         .src_node(tokio::net::get_ip().unwrap())
                //         .dest_node(IpAddr::V4(Ipv4Addr::from_str("100.3.43.125").unwrap()))
                //         .content(buf)
                //         .build(),
                //     "out",
                // )
            }
            _ => {
                let content = msg.cast::<Vec<u8>>().0;
                let msg = DNSMessage::from_buffer(content).unwrap();
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
    server: Option<DNSNameserver>,
}
#[async_trait::async_trait]
impl AsyncModule for DNSServer0 {
    fn new() -> Self {
        Self {
            server: Some(
                DNSNameserver::from_zonefile(
                    "org",
                    "/Users/mk_dev/Developer/rust/inet/bin/zonefiles/",
                )
                .unwrap(),
            ),
        }
    }

    async fn at_sim_start(&mut self, _stage: usize) {
        let ip = par("addr").unwrap().parse::<Ipv4Addr>().unwrap();
        IOContext::new(random(), ip).set();

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

#[NdlModule("bin")]
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
                    "/Users/mk_dev/Developer/rust/inet/bin/zonefiles/",
                )
                .unwrap(),
            ),
        }
    }

    async fn at_sim_start(&mut self, _stage: usize) {
        let ip = par("addr").unwrap().parse::<Ipv4Addr>().unwrap();
        IOContext::new(random(), ip).set();
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

#[NdlModule("bin")]
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
                    "/Users/mk_dev/Developer/rust/inet/bin/zonefiles/",
                )
                .unwrap(),
            ),
        }
    }

    async fn at_sim_start(&mut self, _stage: usize) {
        let ip = par("addr").unwrap().parse::<Ipv4Addr>().unwrap();
        IOContext::new(random(), ip).set();
        schedule_in(Message::new().kind(7912).build(), Duration::from_secs(5));
    }

    async fn handle_message(&mut self, msg: Message) {
        if msg.header().kind != 7912 {
            return;
        }
        let mut server = self.server.take().unwrap();
        tokio::spawn(async move {
            server.launch().await.unwrap();
        });
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
    ScopedLogger::new()
        .interal_max_log_level(log::LevelFilter::Warn)
        .finish()
        .unwrap();

    let rt = Main {}.build_rt();
    let rt = Runtime::new(rt);
    let _ = rt.run();
}
