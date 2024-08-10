use bytepack::ToBytestream;
use des::{prelude::*, registry, time::sleep};
use inet::{
    interface::{add_interface, Interface, NetworkDevice},
    socket::RawIpSocket,
    TcpListener,
};
use inet_types::{
    ip::{IpPacket, Ipv4Flags, Ipv4Packet},
    tcp::{TcpFlags, TcpPacket, PROTO_TCP},
};
use tokio::spawn;

#[derive(Default)]
struct Spoofer {}

impl Module for Spoofer {
    fn at_sim_start(&mut self, _: usize) {
        add_interface(Interface::ethv4(
            NetworkDevice::eth(),
            Ipv4Addr::new(192, 168, 0, 100),
        ))
        .unwrap();
        spawn(async move {
            let sock = RawIpSocket::new_v4().unwrap();
            for i in 0..3 {
                let pkt = IpPacket::V4(Ipv4Packet {
                    enc: 0,
                    dscp: 0,
                    identification: 0,
                    flags: Ipv4Flags {
                        mf: false,
                        df: false,
                    },
                    fragment_offset: 0,
                    ttl: 2,
                    proto: PROTO_TCP,
                    src: Ipv4Addr::new(192, 168, 0, 200),
                    dest: Ipv4Addr::new(192, 168, 0, 1),
                    content: TcpPacket {
                        src_port: 1024 + i,
                        dest_port: 1000,
                        seq_no: 0,
                        ack_no: 0,
                        flags: TcpFlags::new().syn(true),
                        window: 1024,
                        urgent_ptr: 0,
                        options: Vec::new(),
                        content: Vec::new(),
                    }
                    .to_vec()
                    .unwrap(),
                });
                sock.try_send(pkt).unwrap();
                tracing::info!("send syn packet");
                sleep(Duration::from_millis(100)).await;
            }
        });
    }
}

#[derive(Default)]
struct Reader {}

impl Module for Reader {
    fn at_sim_start(&mut self, _stage: usize) {
        add_interface(Interface::ethv4(
            NetworkDevice::eth(),
            Ipv4Addr::new(192, 168, 0, 1),
        ))
        .unwrap();

        spawn(async move {
            let lis = TcpListener::bind((Ipv4Addr::UNSPECIFIED, 1000))
                .await
                .unwrap();
            loop {
                let (stream, from) = match lis.accept().await {
                    Ok(vv) => vv,
                    Err(e) => {
                        eprintln!("{e}");
                        continue;
                    }
                };

                let _ = (stream, from);
            }
        });
    }
}

fn main() {
    des::tracing::init();

    let app = Sim::new(())
        .with_stack(inet::init)
        .with_ndl(
            "inet/src/bin/spoofing.ndl",
            registry![Spoofer, Reader, else _],
        )
        .map_err(|e| println!("{e}"))
        .unwrap();
    let rt = Builder::seeded(123).build(app);
    let _ = rt.run().unwrap();
}
