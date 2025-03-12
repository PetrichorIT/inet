use std::{io::ErrorKind, net::Ipv4Addr, time::Duration};

use des::{
    net::{AsyncFn, Sim},
    prelude::{Channel, ChannelDropBehaviour, ChannelMetrics},
    runtime::Builder,
};
use serial_test::serial;

use inet::interface::{add_interface, InterfaceDef, NetworkDevice};
use inet::tcp2::TcpStream;

#[serial]
#[test]
fn connect_no_local_ip_version() {
    let mut sim = Sim::new(()).with_stack(inet::init);
    sim.node(
        "sender",
        AsyncFn::io(|_| async move {
            add_interface(
                InterfaceDef::new("en0", NetworkDevice::eth())
                    .ip(Ipv4Addr::new(42, 0, 0, 42).into()),
            )?;

            let stream = TcpStream::connect("2000:132:32::0:8000").await;
            let err = stream.unwrap_err();
            println!("{err}");
            assert_eq!(err.kind(), ErrorKind::ConnectionRefused);

            Ok(())
        }),
    );

    sim.node(
        "receiver",
        AsyncFn::new(|_| async move {
            // NOP
        }),
    );

    let a = sim.gate("sender", "port");
    let b = sim.gate("receiver", "port");
    a.connect(
        b,
        Some(Channel::new(ChannelMetrics::new(
            80000,
            Duration::from_millis(200),
            Duration::ZERO,
            ChannelDropBehaviour::Queue(None),
        ))),
    );

    let _ = Builder::seeded(123)
        .max_time(100.0.into())
        .max_itr(100)
        .build(sim)
        .run();
}
