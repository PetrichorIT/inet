use std::{error::Error, fs::File, io::BufWriter};

use des::{prelude::*, registry, tracing::Subscriber};
use inet::interface::{add_interface, Interface, NetworkDevice};
use inet_bgp::{pkt::Nlri, types::AsNumber, BgpDeamon};
use inet_pcap::{PcapCapturePoints, PcapConfig, PcapFilters};

struct BgpNode;
#[async_trait::async_trait]
impl AsyncModule for BgpNode {
    fn new() -> Self {
        Self
    }

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

        let pcap = par("pcap").unwrap().parse::<bool>().unwrap();
        if pcap {
            inet_pcap::pcap(PcapConfig {
                filters: PcapFilters::default(),
                capture: PcapCapturePoints::All,
                output: BufWriter::new(
                    File::create(format!("src/bin/pcap/{}.pcap", module_path())).unwrap(),
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
        for (addr, as_num, iface) in peers {
            deamon = deamon.add_neighbor(addr, as_num, &format!("link-{iface}"))
        }
        for net in nets {
            deamon = deamon.add_nlri(net);
        }

        tokio::spawn(async move {
            let _ = deamon.deploy().await;
        });
    }
}

struct Dummy;
impl Module for Dummy {
    fn new() -> Dummy {
        Dummy
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    inet::init();

    Subscriber::default().init().unwrap();

    type LANSwitch = inet::utils::LinkLayerSwitch;
    type LANNode = Dummy;
    type LANRouter = Dummy;
    type Main = Dummy;
    type LAN = Dummy;

    let mut app = NdlApplication::new(
        "src/bin/bgp.ndl",
        registry![LANNode, LANRouter, LANSwitch, LAN, BgpNode, Main],
    )?
    .into_app();
    app.include_par_file("src/bin/bgp.par");
    let r = Builder::seeded(123)
        .max_time(1000.0.into())
        .build(app)
        .run()
        .into_app();
    r.globals()
        .topology
        .lock()
        .unwrap()
        .write_to_svg("src/bin/topo")?;

    Ok(())
}
