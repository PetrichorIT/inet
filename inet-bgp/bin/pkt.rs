use std::fs::File;

use des::{prelude::*, registry, tokio::spawn, tracing::Subscriber};
use inet::{
    interface::{add_interface, Interface, NetworkDevice},
    pcap::{pcap, PcapCapturePoints, PcapConfig, PcapFilters},
};
use inet_bgp::BgpDeamon;

struct A;
#[async_trait::async_trait]
impl AsyncModule for A {
    fn new() -> Self {
        Self
    }

    async fn at_sim_start(&mut self, _: usize) {
        add_interface(Interface::ethv4(
            NetworkDevice::eth(),
            Ipv4Addr::new(192, 168, 0, 101),
        ))
        .unwrap();

        pcap(PcapConfig {
            filters: PcapFilters::default(),
            capture: PcapCapturePoints::CLIENT_DEFAULT,
            output: File::create("bin/a.pcap").unwrap(),
        })
        .unwrap();

        spawn(
            BgpDeamon::new(1000, Ipv4Addr::new(192, 168, 0, 101))
                .add_neighbor(Ipv4Addr::new(192, 168, 0, 102), 2000)
                .deploy(),
        );

        // spawn(async move {
        //     let sock = TcpSocket::new_v4()?;
        //     sock.bind("192.168.0.101:179".parse().unwrap())?;
        //     let mut stream = sock.connect("192.168.0.102:179".parse().unwrap()).await?;
        //     tracing::info!("stream connected");

        //     let open = BgpPacket {
        //         marker: u128::MAX,
        //         kind: BgpPacketKind::Open(BgpOpenPacket {
        //             version: 4,
        //             as_number: 65033,
        //             hold_time: 180,
        //             identifier: Ipv4Addr::new(192, 168, 0, 101).into(),
        //             options: Vec::new(),
        //         }),
        //     };
        //     stream.write_all(&open.to_buffer().unwrap()).await.unwrap();

        //     let mut buf = [0; 1024];
        //     let n = stream.read(&mut buf).await.unwrap();
        //     let _cfg = BgpPacket::from_buffer(&buf[..n]).unwrap();
        //     tracing::info!("received open / established");

        //     let mut last_keepalive_sent = SimTime::now();

        //     sleep(Duration::from_secs_f64(random::<f64>())).await;

        //     let update = BgpPacket {
        //         marker: u128::MAX,
        //         kind: BgpPacketKind::Update(BgpUpdatePacket {
        //             withdrawn_routes: Vec::new(),
        //             path_attributes: vec![
        //                 BgpPathAttribute {
        //                     flags: BgpPathAttributeFlags {
        //                         optional: false,
        //                         transitiv: true,
        //                         partial: false,
        //                         extended_len: false,
        //                     },
        //                     attr: BgpPathAttributeKind::Origin(BgpPathAttributeOrigin::Egp),
        //                 },
        //                 BgpPathAttribute {
        //                     flags: BgpPathAttributeFlags {
        //                         optional: false,
        //                         transitiv: true,
        //                         partial: false,
        //                         extended_len: false,
        //                     },
        //                     attr: BgpPathAttributeKind::AsPath(BgpPathAttributeAsPath {
        //                         path: vec![123, 1213],
        //                         typ: BgpPathAttributeAsPathTyp::AsSequence,
        //                     }),
        //                 },
        //                 BgpPathAttribute {
        //                     flags: BgpPathAttributeFlags {
        //                         optional: false,
        //                         transitiv: true,
        //                         partial: false,
        //                         extended_len: false,
        //                     },
        //                     attr: BgpPathAttributeKind::NextHop(BgpPathAttributeNextHop {
        //                         hop: Ipv4Addr::new(192, 168, 0, 33),
        //                     }),
        //                 },
        //             ],
        //             nlris: vec![BgpNrli {
        //                 prefix: Ipv4Addr::new(10, 0, 0, 0),
        //                 prefix_len: 8,
        //             }],
        //         }),
        //     };

        //     stream.write_all(&update.to_buffer().unwrap()).await?;

        //     loop {
        //         buf = [0; 1024];
        //         let dur = Duration::from_secs(30)
        //             .checked_sub(SimTime::now() - last_keepalive_sent)
        //             .unwrap_or(Duration::from_secs(1));

        //         tokio::select! {
        //             n = stream.read(&mut buf) => {
        //                 let n = n.unwrap();
        //                 if n == 0 {
        //                     break
        //                 }
        //                 let bgp = BgpPacket::from_buffer(&buf[..n]);
        //                 tracing::debug!("> {bgp:#?}");
        //             },
        //             _ = sleep(dur) => {
        //                 // Send keeapalive
        //                 stream.write_all(&BgpPacket {
        //                     marker: u128::MAX,
        //                     kind: BgpPacketKind::Keepalive()
        //                 }.to_buffer().unwrap()).await?;
        //                 last_keepalive_sent = SimTime::now();
        //             }
        //         }
        //     }

        //     Ok::<_, Error>(())
        // });
    }
}

// ffffffffffffffffffffffffffffffff 00 1d 0104 fe09 00b4c 0a8006500
// ffffffffffffffffffffffffffffffff 00 1d 0104 fe09 00b4c 0a8000f00

struct B;
#[async_trait::async_trait]
impl AsyncModule for B {
    fn new() -> Self {
        Self
    }

    async fn at_sim_start(&mut self, _: usize) {
        add_interface(Interface::ethv4(
            NetworkDevice::eth(),
            Ipv4Addr::new(192, 168, 0, 102),
        ))
        .unwrap();

        pcap(PcapConfig {
            filters: PcapFilters::default(),
            capture: PcapCapturePoints::CLIENT_DEFAULT,
            output: File::create("bin/b.pcap").unwrap(),
        })
        .unwrap();

        spawn(
            BgpDeamon::new(1000, Ipv4Addr::new(192, 168, 0, 102))
                .add_neighbor(Ipv4Addr::new(192, 168, 0, 101), 1000)
                .deploy(),
        );

        // spawn(async move {
        //     let sock = TcpSocket::new_v4()?;
        //     sock.bind("192.168.0.102:179".parse().unwrap())?;
        //     let mut stream = sock.connect("192.168.0.101:179".parse().unwrap()).await?;
        //     tracing::info!("stream connected");

        //     let mut buf = [0; 1024];
        //     let n = stream.read(&mut buf).await.unwrap();
        //     let _cfg = BgpPacket::from_buffer(&buf[..n]).unwrap();
        //     tracing::info!("received open / responding");
        //     let open = BgpPacket {
        //         marker: u128::MAX,
        //         kind: BgpPacketKind::Open(BgpOpenPacket {
        //             version: 4,
        //             as_number: 65099,
        //             hold_time: 180,
        //             identifier: Ipv4Addr::new(192, 168, 0, 102).into(),
        //             options: Vec::new(),
        //         }),
        //     };
        //     stream.write_all(&open.to_buffer().unwrap()).await?;

        //     let mut last_keepalive_sent = SimTime::now();

        //     sleep(Duration::from_secs_f64(random::<f64>())).await;

        //     let notif = BgpPacket {
        //         marker: u128::MAX,
        //         kind: BgpPacketKind::Notification(BgpNotificationPacket::UpdateMessageError(
        //             BgpUpdateMessageError::InvalidOriginAttribute,
        //         )),
        //     };
        //     stream.write_all(&notif.to_buffer().unwrap()).await.unwrap();

        //     loop {
        //         buf = [0; 1024];
        //         let dur = Duration::from_secs(30)
        //             .checked_sub(SimTime::now() - last_keepalive_sent)
        //             .unwrap_or(Duration::from_secs(1));

        //         tokio::select! {
        //             n = stream.read(&mut buf) => {
        //                 let n = n.unwrap();
        //                 if n == 0 {
        //                     break
        //                 }

        //                 let bgp = BgpPacket::from_buffer(&buf[..n]);
        //                 tracing::debug!("> {bgp:#?}");
        //             },
        //             _ = sleep(dur) => {
        //                 // Send keeapalive
        //                 stream.write_all(&BgpPacket {
        //                     marker: u128::MAX,
        //                     kind: BgpPacketKind::Keepalive()
        //                 }.to_buffer().unwrap()).await?;
        //                 last_keepalive_sent = SimTime::now();
        //             }
        //         }
        //     }
        //     Ok::<_, Error>(())
        // });
    }
}

struct Main;
impl Module for Main {
    fn new() -> Self {
        Self
    }
}

fn main() {
    inet::init();

    Subscriber::default().init().unwrap();

    let app =
        NetworkApplication::new(NdlApplication::new("bin/pkt.ndl", registry![A, B, Main]).unwrap());
    let rt = Runtime::new_with(
        app,
        RuntimeOptions::seeded(123)
            .max_time(1000.0.into())
            .max_itr(1000),
    );
    let _ = rt.run();
}
