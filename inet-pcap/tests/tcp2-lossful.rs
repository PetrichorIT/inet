use std::{fs::File, net::Ipv4Addr, sync::Arc, time::Duration};

use des::{
    net::{
        handlers::{AsyncHandler, HandlerFn},
        Sim,
    },
    prelude::{send, ChannelDropBehaviour, DatarateChannel, DatarateChannelMetrics},
    runtime::{random, Builder},
};
use inet::{
    interface::{add_interface, InterfaceDef, NetworkDevice},
    tcp2::{TcpListener, TcpStream},
};
use inet_pcap::pcap;
use rand::RngCore;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[test]
fn lossfull_stream() {
    // des::tracing::init();

    let mut bytes = vec![0; 10_000]; // 8MB;
    rand::rng().fill_bytes(&mut bytes);

    let bytes = Arc::new(bytes);
    let bytes2 = bytes.clone();

    let mut sim = Sim::new(()).with_stack(inet::init);
    sim.node(
        "client",
        AsyncHandler::io(move |_| {
            let bytes = bytes.clone();
            async move {
                add_interface(
                    InterfaceDef::new("en0", NetworkDevice::eth())
                        .ip(Ipv4Addr::new(192, 168, 2, 100).into()),
                )
                .unwrap();

                pcap(File::create("out/tcp2-lossful-client.pcap").unwrap()).unwrap();

                let mut sock = TcpStream::connect(("192.168.2.200", 80)).await?;
                sock.write_all(&bytes).await?;

                Ok(())
            }
        }),
    );

    sim.node(
        "server",
        AsyncHandler::io(move |_| {
            let bytes = bytes2.clone();
            async move {
                add_interface(
                    InterfaceDef::new("en0", NetworkDevice::eth())
                        .ip(Ipv4Addr::new(192, 168, 2, 200).into()),
                )
                .unwrap();

                // pcap(File::create("out/tcp2-lossful-server.pcap").unwrap()).unwrap();

                let lis = TcpListener::bind(("0.0.0.0", 80)).await?;
                let (mut stream, _) = lis.accept().await?;

                let mut buf = [0; 1024];
                let mut rem = &bytes[..];
                while !rem.is_empty() {
                    let n = stream.read(&mut buf).await.map_err(|e| e)?;
                    if n == 0 {
                        tracing::info!("recv closed of zero read");
                        break;
                    }

                    tracing::info!("read {n} bytes");

                    assert_eq!(&rem[..n], &buf[..n]);
                    rem = &rem[n..];
                }

                Ok(())
            }
        }),
    );

    sim.node(
        "link",
        HandlerFn::new(|msg| match msg.header.last_gate.as_ref().unwrap().name() {
            "port-client" if random::<u8>() > 32 => {
                let _ = send(msg, "port-server");
            }
            "port-server" if random::<u8>() > 32 => {
                let _ = send(msg, "port-client");
            }
            _ => tracing::error!(
                kind = msg.header.kind,
                "dropping packet from {:?}",
                msg.header.last_gate
            ),
        }),
    );

    let a = sim.gate("client", "port");
    let aa = sim.gate("link", "port-client");

    let b = sim.gate("server", "port");
    let bb = sim.gate("link", "port-server");

    a.connect_with(
        aa,
        Some(DatarateChannel::new(DatarateChannelMetrics::new(
            8000000,
            Duration::from_millis(20),
            Duration::ZERO,
            ChannelDropBehaviour::Queue(None),
        ))),
    );

    b.connect_with(
        bb,
        Some(DatarateChannel::new(DatarateChannelMetrics::new(
            8000000,
            Duration::from_millis(20),
            Duration::ZERO,
            ChannelDropBehaviour::Queue(None),
        ))),
    );

    let rt = Builder::seeded(123)
        .max_time(1000.0.into())
        .build(sim.freeze());
    let (_, _, _) = rt.run().unwrap();
}
