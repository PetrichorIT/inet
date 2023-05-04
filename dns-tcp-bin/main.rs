use des::{
    prelude::*,
    registry,
    tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        task::JoinHandle,
        time::sleep,
    },
};
use inet::{
    dns::*,
    interface::{add_interface, Interface, NetworkDevice},
    routing::{add_routing_entry, set_default_gateway, RoutingInformation},
    TcpListener, TcpStream,
};
use inet_types::ip::IpMask;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

struct Node {
    recv_bytes: Arc<AtomicUsize>,
    handle: Option<JoinHandle<usize>>,
}
#[async_trait::async_trait]
impl AsyncModule for Node {
    fn new() -> Node {
        Node {
            recv_bytes: Arc::new(AtomicUsize::new(0)),
            handle: None,
        }
    }

    fn num_sim_start_stages(&self) -> usize {
        2
    }

    async fn at_sim_start(&mut self, stage: usize) {
        if stage == 0 {
            return;
        }

        let gateway = par("gateway").unwrap().parse().unwrap();
        let addr = par("addr").unwrap().parse().unwrap();
        let mask = par("mask").unwrap().parse().unwrap();

        add_interface(Interface::ethv4_named(
            "en0",
            NetworkDevice::eth(),
            addr,
            mask,
        ))
        .unwrap();
        add_interface(Interface::loopback()).unwrap();

        set_default_gateway(gateway).unwrap();

        let recv = self.recv_bytes.clone();
        tokio::spawn(async move {
            let lis = TcpListener::bind("0.0.0.0:5000").await.unwrap();
            loop {
                let (mut stream, _) = lis.accept().await.unwrap();
                let mut buf = [0; 512];
                let n = stream.read(&mut buf).await.unwrap();
                recv.fetch_add(n, Ordering::SeqCst);
            }
        });

        tokio::spawn(async move {
            let mut server = DNSNameserver::client(addr.into());

            server.allow_recursive_for(IpMask::catch_all_v4());
            server.launch().await.unwrap();
        });

        self.handle = Some(tokio::spawn(async move {
            let mut n = 0;
            loop {
                sleep(Duration::from_secs_f64(random::<f64>())).await;

                let target = DOMAINS[random::<usize>() % DOMAINS.len()];
                let mut stream = TcpStream::connect((target, 5000)).await.unwrap();

                stream.write(&[42; 100]).await.unwrap();
                n += 100;

                if SimTime::now().as_secs() > 99 {
                    break;
                }
            }
            n
        }));
    }

    async fn at_sim_end(&mut self) {
        let send = par_for("send", "").unwrap().parse::<usize>().unwrap()
            + self.handle.take().unwrap().await.unwrap();
        let recv = par_for("recv", "").unwrap().parse::<usize>().unwrap()
            + self.recv_bytes.load(Ordering::SeqCst);

        par_for("send", "").set(send).unwrap();
        par_for("recv", "").set(recv).unwrap();
    }
}

struct Dns {}
#[async_trait::async_trait]
impl AsyncModule for Dns {
    fn new() -> Self {
        Self {}
    }

    fn num_sim_start_stages(&self) -> usize {
        2
    }

    async fn at_sim_start(&mut self, stage: usize) {
        if stage == 0 {
            return;
        }

        let gateway = par("gateway").unwrap().parse().unwrap();
        let addr = par("addr").unwrap().parse().unwrap();
        let mask = par("mask").unwrap().parse().unwrap();

        add_interface(Interface::ethv4_named(
            "en0",
            NetworkDevice::eth(),
            addr,
            mask,
        ))
        .unwrap();
        add_interface(Interface::loopback()).unwrap();

        set_default_gateway(gateway).unwrap();

        let zone = par("zone").unwrap().into_inner();
        let domain_name = par("domain").unwrap().into_inner();

        tokio::spawn(async move {
            let mut dns =
                DNSNameserver::from_zonefile(&zone, "dns-tcp-bin/zonefiles", domain_name).unwrap();
            if zone == "." {
                dns.declare_root_ns();
            }
            dns.launch().await.unwrap();
        });
    }
}

struct Router {}
impl Module for Router {
    fn new() -> Router {
        Router {}
    }

    fn num_sim_start_stages(&self) -> usize {
        2
    }

    fn at_sim_start(&mut self, stage: usize) {
        if stage == 0 {
            return;
        }

        let info = RoutingInformation::collect();

        let addr = par("addr").unwrap().parse().unwrap();
        let mask = par("mask").unwrap().parse().unwrap();

        add_interface(Interface::ethv4_named(
            "lan",
            NetworkDevice::eth_select(|r| r.name == "lan_"),
            addr,
            mask,
        ))
        .unwrap();

        log::info!(
            "router with {} connections, self =  {addr}",
            info.ports.len()
        );

        for i in 0..3 {
            // routing entries to associated networks
            let module = gate("wan_out", i)
                .unwrap()
                .path_end()
                .unwrap()
                .owner()
                .path();

            let taddr: Ipv4Addr = par_for("addr", &module).unwrap().parse().unwrap();
            let tmask = par_for("mask", &module).unwrap().parse().unwrap();

            add_interface(Interface::ethv4_named(
                format!("wan{i}"),
                NetworkDevice::eth_select(|r| r.name == "wan_" && r.output.pos() == i),
                addr,
                Ipv4Addr::BROADCAST,
            ))
            .unwrap();

            let oct = taddr.octets();
            let tsubnet = Ipv4Addr::from([oct[0], oct[1], oct[2], 0]);

            log::debug!("routing to subnet {tsubnet}/{tmask} via wan{i} ({taddr})");
            add_routing_entry(tsubnet, tmask, taddr, &format!("wan{i}")).unwrap();
        }
    }

    fn handle_message(&mut self, msg: Message) {
        panic!("{msg:?}")
    }
}

type Switch = inet::utils::LinkLayerSwitch;

const DOMAINS: [&str; 10] = [
    "www.example.org",
    "ftp.example.org",
    "log.example.org",
    "info.example.org",
    "admin.example.org",
    "www.test.org",
    "ftp.test.org",
    "log.test.org",
    "info.test.org",
    "admin.test.org",
];

struct LAN;
impl Module for LAN {
    fn new() -> LAN {
        LAN
    }

    fn at_sim_start(&mut self, _stage: usize) {
        let addr: Ipv4Addr = par("addr").unwrap().parse().unwrap();
        let mask: Ipv4Addr = par("addr").unwrap().parse().unwrap();

        let oct = addr.octets();
        let router = Ipv4Addr::new(oct[0], oct[1], oct[2], 1);
        par_for("addr", format!("{}.router", module_name()))
            .set(router)
            .unwrap();
        par_for("mask", format!("{}.router", module_name()))
            .set(mask)
            .unwrap();

        let mut addrs = Vec::new();

        for i in 0..5 {
            let addr = Ipv4Addr::new(oct[0], oct[1], oct[2], 100 + i);
            addrs.push(addr);
            par_for("gateway", format!("{}.node[{i}]", module_name()))
                .set(router)
                .unwrap();
            par_for("addr", format!("{}.node[{i}]", module_name()))
                .set(addr)
                .unwrap();
            par_for("mask", format!("{}.node[{i}]", module_name()))
                .set(mask)
                .unwrap();
        }

        if module_name() == "d" {
            return;
        }

        let addrs = addrs
            .into_iter()
            .map(|v| v.to_string())
            .fold(String::new(), |mut acc, c| {
                acc.push_str(&c);
                acc.push(',');
                acc
            });

        let par = par_for("addrs", "");
        let s = if par.is_some() {
            par.clone().unwrap().into_inner() + "," + &addrs
        } else {
            addrs
        };

        par.set(s).unwrap();
    }
}

struct Main;
impl Module for Main {
    fn new() -> Main {
        Main
    }

    fn at_sim_start(&mut self, _stage: usize) {
        par("send").set("0").unwrap();
        par("recv").set("0").unwrap();
    }

    fn at_sim_end(&mut self) {
        assert_eq!(
            par("send").unwrap().parse::<usize>().unwrap(),
            par("recv").unwrap().parse::<usize>().unwrap()
        );

        // println!(
        //     "{:#?}",
        //     par("addrs")
        //         .unwrap()
        //         .into_inner()
        //         .split(",")
        //         .map(|v| v.parse::<Ipv4Addr>())
        //         .flatten()
        //         .collect::<Vec<_>>()
        // );

        log::info!(
            "processed {} bytes",
            par("recv").unwrap().parse::<usize>().unwrap()
        );
    }
}

fn main() {
    inet::init();
    // Logger::new()
    // .interal_max_log_level(log::LevelFilter::Trace)
    // .set_logger();

    let app = NdlApplication::new(
        "dns-tcp-bin/main.ndl",
        registry![Node, Router, Switch, LAN, Main, Dns],
    )
    .map_err(|e| println!("{e}"))
    .unwrap();
    let mut app = NetworkApplication::new(app);
    app.include_par_file("dns-tcp-bin/main.par");
    let rt = Runtime::new_with(app, RuntimeOptions::seeded(123));
    let (app, _, _) = rt.run().unwrap();

    println!(
        "{:?}",
        app.globals()
            .topology
            .lock()
            .unwrap()
            .all_links_bidiretional()
    );
}
