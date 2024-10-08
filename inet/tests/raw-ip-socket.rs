use std::{
    iter,
    sync::atomic::{AtomicUsize, Ordering},
};

use des::{prelude::*, registry, time::sleep};
use inet::{
    interface::{add_interface, Interface, NetworkDevice},
    socket::RawIpSocket,
};
use tokio::spawn;
use types::ip::{IpPacket, Ipv4Flags, Ipv4Packet, Ipv6Packet};

const PROTO: u8 = 83;

static V4: AtomicUsize = AtomicUsize::new(0);
static V6: AtomicUsize = AtomicUsize::new(0);

#[derive(Default)]
struct Emitter;

impl Module for Emitter {
    fn at_sim_start(&mut self, _stage: usize) {
        add_interface(Interface::eth_mixed(
            "en0",
            NetworkDevice::eth(),
            (
                Ipv4Addr::new(192, 168, 0, 103),
                Ipv4Addr::new(255, 255, 255, 0),
            ),
            ("fe80::02".parse::<Ipv6Addr>().unwrap(), 64),
        ))
        .unwrap();

        spawn(async move {
            let sockv4 = RawIpSocket::new_v4().unwrap();
            sockv4.bind_proto(PROTO).unwrap();

            let sockv6 = RawIpSocket::new_v6().unwrap();
            sockv6.bind_proto(PROTO).unwrap();

            for i in 1..10 {
                sleep(Duration::from_secs(1)).await;
                let v4 = random::<bool>();
                if v4 {
                    let pkt = Ipv4Packet {
                        dscp: 0,
                        enc: 0,
                        identification: i,
                        flags: Ipv4Flags {
                            df: false,
                            mf: false,
                        },
                        fragment_offset: 0,
                        ttl: 64,
                        proto: PROTO,
                        src: Ipv4Addr::new(192, 168, 0, 103),
                        dst: Ipv4Addr::new(192, 168, 0, 1),
                        content: iter::repeat_with(|| random::<u8>()).take(16).collect(),
                    };
                    tracing::info!("v4::sending {:?}", pkt.content);

                    sockv4.try_send(IpPacket::V4(pkt)).unwrap();
                    V4.fetch_add(1, Ordering::SeqCst);
                } else {
                    let pkt = Ipv6Packet {
                        traffic_class: 0,
                        flow_label: i as u32,
                        next_header: PROTO,
                        hop_limit: 64,
                        src: "fe80::02".parse::<Ipv6Addr>().unwrap(),
                        dst: "fe80::01".parse::<Ipv6Addr>().unwrap(),
                        content: iter::repeat_with(|| random::<u8>()).take(16).collect(),
                    };

                    tracing::info!("v6::sending {:?}", pkt.content);
                    sockv6.try_send(IpPacket::V6(pkt)).unwrap();
                    V6.fetch_add(1, Ordering::SeqCst);
                }
            }
        });
    }

    fn at_sim_end(&mut self) {
        assert_eq!(V4.load(Ordering::SeqCst), 0);
        assert_eq!(V6.load(Ordering::SeqCst), 0);
    }
}

#[derive(Default)]
struct Receiver;

impl Module for Receiver {
    fn at_sim_start(&mut self, _: usize) {
        add_interface(Interface::eth_mixed(
            "en0",
            NetworkDevice::eth(),
            (
                Ipv4Addr::new(192, 168, 0, 1),
                Ipv4Addr::new(255, 255, 255, 0),
            ),
            ("fe80::01".parse::<Ipv6Addr>().unwrap(), 64),
        ))
        .unwrap();

        spawn(async move {
            let mut sock = RawIpSocket::new_v4().unwrap();
            sock.bind_proto(PROTO).unwrap();
            while let Ok(pkt) = sock.recv().await {
                tracing::info!("v4::received {:?}", pkt.content());
                V4.fetch_sub(1, Ordering::SeqCst);
            }
        });

        spawn(async move {
            let mut sock = RawIpSocket::new_v6().unwrap();
            sock.bind_proto(PROTO).unwrap();
            while let Ok(pkt) = sock.recv().await {
                tracing::info!("v6::received {:?}", pkt.content());
                V6.fetch_sub(1, Ordering::SeqCst);
            }
        });
    }
}

#[test]
fn raw_ip_socket() {
    // Logger::new()
    // .interal_max_log_level(tracing::LevelFilter::Trace)
    // .set_logger();

    let rt: Sim<_> = Sim::new(())
        .with_stack(inet::init)
        .with_ndl("tests/emit.yml", registry![Emitter, Receiver, else _])
        .map_err(|e| println!("{e}"))
        .unwrap();
    let rt = Builder::seeded(123).build(rt);
    let _ = rt.run();
}
