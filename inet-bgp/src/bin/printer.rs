use std::{fs::File, net::Ipv4Addr};

use des::{net::AsyncBuilder, runtime::Builder};
use inet::{
    interface::{add_interface, Interface, NetworkDevice},
    TcpListener, TcpStream,
};
use inet_pcap::{pcap, PcapCapturePoints, PcapConfig, PcapFilters};
use tokio::io::AsyncWriteExt;

fn main() {
    let mut sim = AsyncBuilder::new();
    sim.node("client", |_| async move {
        add_interface(Interface::ethv4(
            NetworkDevice::eth(),
            Ipv4Addr::new(192, 168, 2, 103),
        ))?;
        pcap(PcapConfig {
            filters: PcapFilters::default(),
            capture: PcapCapturePoints::All,
            output: File::create("single-pkt.pcap").unwrap(),
        })?;

        let mut s = TcpStream::connect("192.168.2.100:179").await?;
        s.write_all(&[
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 0, 52, 2, 0,
            0, 0, 20, 64, 1, 1, 1, 64, 2, 6, 2, 1, 0, 0, 3, 232, 128, 3, 4, 10, 0, 0, 1, 16, 10, 2,
            16, 10, 3, 16, 10, 4, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
            255, 255, 255, 0, 55, 2, 0, 0, 0, 28, 64, 1, 1, 1, 64, 2, 14, 2, 3, 0, 0, 3, 232, 0, 0,
            7, 208, 0, 0, 15, 160, 128, 3, 4, 10, 0, 0, 1, 24, 40, 3, 7,
        ])
        .await?;
        Ok(())
    });
    sim.node("server", |_| async move {
        add_interface(Interface::ethv4(
            NetworkDevice::eth(),
            Ipv4Addr::new(192, 168, 2, 100),
        ))?;
        let l = TcpListener::bind("0.0.0.0:179").await?;
        let _s = l.accept().await?;
        Ok(())
    });
    sim.connect("client", "server");
    let _ = Builder::seeded(123).build(sim.build()).run();
}
