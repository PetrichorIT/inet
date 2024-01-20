use std::{fs::File, time::Duration};

use des::{
    net::{
        channel::{Channel, ChannelDropBehaviour, ChannelMetrics},
        module::{AsyncModule, Module},
        NetworkApplication,
    },
    runtime::Builder,
};
use inet::{
    interface::{add_interface, Interface, NetworkDevice},
    routing::{declare_ipv6_router, Ipv6RouterConfig, Ipv6RoutingPrefix},
};
use inet_pcap::{pcap, PcapCapturePoints, PcapConfig, PcapFilters};

#[macro_use]
mod common;

struct Host;
impl_build_named!(Host);

impl AsyncModule for Host {
    fn new() -> Self {
        Self
    }

    async fn at_sim_start(&mut self, _stage: usize) {
        tracing::info!("HELLO");

        pcap(PcapConfig {
            filters: PcapFilters::default(),
            capture: PcapCapturePoints::All,
            output: File::create("out/ipv6_icmp_stack.pcap").unwrap(),
        })
        .unwrap();

        add_interface(Interface::ethv6_autocfg(NetworkDevice::eth())).unwrap();
    }
}

struct Router;
impl_build_named!(Router);

impl AsyncModule for Router {
    fn new() -> Self {
        Self
    }

    async fn at_sim_start(&mut self, _stage: usize) {
        pcap(PcapConfig {
            filters: PcapFilters::default(),
            capture: PcapCapturePoints::All,
            output: File::create("out/ipv6_icmp_stack_router.pcap").unwrap(),
        })
        .unwrap();

        let mut iface = Interface::ethv6_named(
            "port-0",
            NetworkDevice::eth(),
            "fe80::abcd".parse().unwrap(),
        );
        iface.flags.router = true;
        add_interface(iface).unwrap();

        declare_ipv6_router(Ipv6RouterConfig {
            current_hop_limit: 255,
            managed: false,
            other_cfg: false,
            lifetime: Duration::from_secs(9000),
            reachable_time: Duration::from_secs(90),
            retransmit_time: Duration::from_secs(90),
            prefixes: vec![
                Ipv6RoutingPrefix {
                    prefix_len: 64,
                    prefix: "2003:c1:e719:8fff::".parse().unwrap(),
                },
                Ipv6RoutingPrefix {
                    prefix_len: 64,
                    prefix: "2003:c1:e719:1234::".parse().unwrap(),
                },
            ],
        })
        .unwrap();
    }
}

#[test]
fn ipv6_autcfg() {
    inet::init();
    des::tracing::Subscriber::default().init().unwrap();

    let mut app = NetworkApplication::new(());
    let host = Host::build_named("host".parse().unwrap(), &mut app);
    let router = Router::build_named("router".parse().unwrap(), &mut app);

    let hp = host.create_gate("port");
    let rp = router.create_gate("port");

    hp.connect(
        rp,
        Some(Channel::new(
            router.path().appended_channel("channel"),
            ChannelMetrics {
                bitrate: 1_000_000,
                latency: Duration::from_millis(5),
                jitter: Duration::ZERO,
                drop_behaviour: ChannelDropBehaviour::Drop,
            },
        )),
    );

    app.register_module(host);
    app.register_module(router);

    let rt = Builder::seeded(123).max_time(10.0.into()).build(app);
    let _ = rt.run();
}
