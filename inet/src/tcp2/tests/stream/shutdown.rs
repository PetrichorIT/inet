use std::{net::Ipv4Addr, time::Duration};

use des::{
    net::{AsyncFn, Sim},
    prelude::{Channel, ChannelDropBehaviour, ChannelMetrics},
    runtime::Builder,
};
use serial_test::serial;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::{
    interface::{add_interface, Interface, NetworkDevice},
    socket::{bsd_socket_info, AsRawFd},
    TcpListener, TcpStream,
};

#[test]
#[serial]
fn test_tcp_removes_tcb() {
    let mut sim = Sim::new(()).with_stack(crate::init);
    sim.node(
        "client",
        AsyncFn::io(|_| async move {
            add_interface(Interface::ethv4(
                NetworkDevice::eth(),
                Ipv4Addr::new(192, 168, 2, 100),
            ))
            .unwrap();

            let mut sock = TcpStream::connect(("192.168.2.200", 80)).await?;
            let fd = sock.as_raw_fd();

            assert!(bsd_socket_info(fd).is_ok());
            sock.write_all(b"Hello World!").await?;
            drop(sock);

            des::time::sleep(Duration::from_secs(3)).await;
            assert!(bsd_socket_info(fd).is_err());

            Ok(())
        }),
    );

    sim.node(
        "server",
        AsyncFn::io(|_| async move {
            add_interface(Interface::ethv4(
                NetworkDevice::eth(),
                Ipv4Addr::new(192, 168, 2, 200),
            ))
            .unwrap();

            let lis = TcpListener::bind(("0.0.0.0", 80)).await?;
            let (mut stream, _) = lis.accept().await?;

            let fd = stream.as_raw_fd();
            assert!(bsd_socket_info(fd).is_ok());

            let mut buf = [0; 200];
            let n = stream.read(&mut buf).await?;
            assert_eq!(&buf[..n], b"Hello World!");

            drop(stream); // close, send fin
            des::time::sleep(Duration::from_secs(3)).await; // wait for ack of fin

            // Check off
            assert!(bsd_socket_info(fd).is_err());

            drop(lis);

            Ok(())
        }),
    );

    let a = sim.gate("client", "port");
    let b = sim.gate("server", "port");

    a.connect(
        b,
        Some(Channel::new(ChannelMetrics::new(
            8000000,
            Duration::from_millis(20),
            Duration::ZERO,
            ChannelDropBehaviour::Queue(None),
        ))),
    );

    let rt = Builder::seeded(123).build(sim);
    let (_, _, _) = rt.run().unwrap();
}
