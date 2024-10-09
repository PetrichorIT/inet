use std::{io::ErrorKind, net::Ipv4Addr, time::Duration};

use des::{
    net::{AsyncFn, Sim},
    prelude::{Channel, ChannelDropBehaviour, ChannelMetrics},
    runtime::Builder,
};
use serial_test::serial;

use inet::interface::{add_interface, Interface, NetworkDevice};
use inet::tcp2::TcpStream;

#[serial]
#[test]
fn connect_no_local_ip_version() {
    des::tracing::init();

    let mut sim = Sim::new(()).with_stack(inet::init);
    sim.node(
        "alice",
        AsyncFn::io(|_| async move {
            add_interface(Interface::ethv4(
                NetworkDevice::eth(),
                Ipv4Addr::new(42, 0, 0, 42),
            ))?;

            let stream = TcpStream::connect("2000:132:32::0:8000").await;
            let err = stream.unwrap_err();
            println!("{err}");
            assert_eq!(err.kind(), ErrorKind::ConnectionRefused);

            Ok(())
        }),
    );

    sim.node(
        "bob",
        AsyncFn::new(|_| async move {
            // NOP
        }),
    );

    let a = sim.gate("alice", "port");
    let b = sim.gate("bob", "port");
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
