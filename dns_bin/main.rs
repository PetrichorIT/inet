use des::{net::hooks::*, prelude::*, tokio::net::IOContext};
use inet::{dns::*, FromBytestream, IpMask};

/*
Concept
DNS0 = org
DNS1 = example
DNS2 = www
*/

// # CLIENT

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
                // let lookup = self
                //     .resolver
                //     ._lookup_host("www.Example.Org")
                //     .await
                //     .solve_with_socket()
                //     .await
                //     .unwrap();
                // // let lookup = self.resolver.lookup_host("www.example.org").await.unwrap();
                // for ip in lookup {
                //     log::info!(">>>>> {}", ip)
                // }

                // log::warn!("Staring second resolve");

                // let lookup = self
                //     .resolver
                //     ._lookup_host("www.example.org")
                //     .await
                //     .solve_with_socket()
                //     .await
                //     .unwrap();

                // for ip in lookup {
                //     log::info!(">>>>> {}", ip)
                // }

                // // let msg = DNSMessage::question_a(7523, "www.example.org.");

                // // let buf = msg.into_buffer().unwrap();
                // // // println!("{:?}", buf);
                // // send(
                // //     Message::new()
                // //         .src_node(tokio::net::get_ip().unwrap())
                // //         .dest_node(IpAddr::V4(Ipv4Addr::from_str("100.3.43.125").unwrap()))
                // //         .content(buf)
                // //         .build(),
                // //     "out",
                // // )

                let lookup = lookup_host("www.example.org:80").await;
                match lookup {
                    Ok(iter) => {
                        for addr in iter {
                            log::info!(">>> {}", addr)
                        }
                    }
                    Err(e) => log::error!(">>> {}", e),
                }

                // let socket = UdpSocket::bind("0.0.0.0:0").await.unwrap();
                // let mut msg = DNSMessage::question_a(123, "www.example.aaa");
                // msg.rd = true;
                // let buf = msg.into_buffer().unwrap();
                // socket
                //     .send_to(&buf, SocketAddr::from_str("127.0.0.1:53").unwrap())
                //     .await
                //     .unwrap();

                // log::info!("Client socket send");

                // let mut buf = vec![0u8; 512];
                // let (n, _) = socket.recv_from(&mut buf).await.unwrap();
                // buf.truncate(n);
                // let resp = DNSMessage::from_buffer(buf).unwrap();

                // log::info!(">>> {:?}", resp.rcode);
                // for response in resp.response() {
                //     log::info!(">>> {}", response);
                // }

                // tokio::time::sleep(Duration::from_secs(100000)).await;

                // let socket = UdpSocket::bind("0.0.0.0:0").await.unwrap();
                // let mut msg = DNSMessage::question_a(812, "www.example.org");
                // msg.rd = true;
                // let buf = msg.into_buffer().unwrap();
                // socket
                //     .send_to(&buf, SocketAddr::from_str("192.168.2.178:53").unwrap())
                //     .await
                //     .unwrap();

                // let mut buf = vec![0u8; 512];
                // let (n, _) = socket.recv_from(&mut buf).await.unwrap();
                // buf.truncate(n);
                // let resp = DNSMessage::from_buffer(buf).unwrap();

                // for response in resp.response() {
                //     log::info!(">>> {}", response);
                // }
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
struct DNSLocal {}

#[async_trait::async_trait]
impl AsyncModule for DNSLocal {
    fn new() -> Self {
        Self {}
    }

    async fn at_sim_start(&mut self, _: usize) {
        let ip = par("addr").unwrap().parse::<Ipv4Addr>().unwrap();
        IOContext::new(random(), ip).set();
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
}

// # SERVER

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
                    "ns0.namservers.org.",
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
                    "a.root-servers.net.",
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
            server.declare_root_ns();
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
