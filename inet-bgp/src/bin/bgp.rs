use std::{error::Error, fs::File, io::BufWriter};

use des::{prelude::*, registry, time::sleep_until};
use inet::{
    interface::{add_interface, Interface, NetworkDevice},
    routing::route,
};
use inet_bgp::{pkt::Nlri, types::AsNumber, BgpDeamon};
use inet_pcap::{PcapCapturePoints, PcapConfig, PcapFilters};

#[derive(Default)]
struct BgpNode;

impl AsyncModule for BgpNode {
    async fn at_sim_start(&mut self, _: usize) {
        let addr = par("addr").unwrap().parse::<Ipv4Addr>().unwrap();
        let as_num = par("as").unwrap().parse::<u16>().unwrap();
        let nets = par("nets")
            .unwrap()
            .split(',')
            .map(|v| v.trim().parse::<Nlri>())
            .flatten()
            .collect::<Vec<_>>();

        let peers = par("peers")
            .unwrap()
            .split(",")
            .map(|s| {
                let split = s.split('/').collect::<Vec<_>>();
                assert_eq!(split.len(), 3);
                (
                    split[0].trim().parse::<Ipv4Addr>().unwrap(),
                    split[1].trim().parse::<AsNumber>().unwrap(),
                    split[2].trim().parse::<usize>().unwrap(),
                )
            })
            .collect::<Vec<_>>();

        let shutdown = par("shutdown")
            .as_option()
            .map(|s| SimTime::from(s.parse::<f64>().unwrap()));
        let restart = par("restart")
            .as_option()
            .map(|s| SimTime::from(s.parse::<f64>().unwrap()));

        let pcap = par("pcap").unwrap().parse::<bool>().unwrap();
        if pcap {
            inet_pcap::pcap(PcapConfig {
                filters: PcapFilters::default(),
                capture: PcapCapturePoints::All,
                output: BufWriter::new(
                    File::create(format!("src/bin/pcap/{}.pcap", current().path())).unwrap(),
                ),
            })
            .unwrap();
        }

        for &(peer_addr, _, iface) in &peers {
            let device = NetworkDevice::eth_select(|r| r.input.pos() == iface);

            let xored = u32::from(addr) ^ u32::from(peer_addr);
            let n = xored.leading_zeros();
            let mask = Ipv4Addr::from(!(u32::MAX >> n));

            add_interface(Interface::ethv4_named(
                format!("link-{iface}"),
                device,
                addr,
                mask,
            ))
            .unwrap();
        }

        let mut deamon = BgpDeamon::new(as_num, addr);
        for &(addr, as_num, iface) in &peers {
            deamon = deamon.add_neighbor(addr, as_num, &format!("link-{iface}"))
        }
        for net in nets {
            deamon = deamon.add_nlri(net);
        }

        tokio::spawn(async move {
            let mng = deamon.deploy().await.unwrap();

            if let Some(shutdown) = shutdown {
                sleep_until(shutdown).await;
                for peer in &peers {
                    mng.send(inet_bgp::BgpDeamonManagmentEvent::StopPeering(peer.0))
                        .await
                        .unwrap();
                }
            }

            if let Some(restart) = restart {
                sleep_until(restart).await;
                for peer in &peers {
                    mng.send(inet_bgp::BgpDeamonManagmentEvent::StartPeering(peer.0))
                        .await
                        .unwrap();
                }
            }

            sleep_until(499.0.into()).await;
            mng.send(inet_bgp::BgpDeamonManagmentEvent::Status)
                .await
                .unwrap();
        });
    }

    async fn at_sim_end(&mut self) {
        for route in route().unwrap() {
            tracing::debug!("{route}")
        }
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    inet::init();
    // des::tracing::init();

    type LANSwitch = inet::utils::LinkLayerSwitch;

    let mut app = Sim::ndl("src/bin/bgp.ndl", registry![LANSwitch, BgpNode, else _])?;
    app.include_par_file("src/bin/bgp.par").unwrap();
    let _r = Builder::seeded(123)
        .max_time(500.0.into())
        .build(app)
        .run()
        .into_app();
    // r.globals().topology.borrow().write_to_svg("src/bin/topo")?;

    Ok(())
}
