use std::{net::Ipv4Addr, time::Duration};

use des::{
    net::{Sim, handlers::AsyncHandler},
    prelude::{ChannelDropBehaviour, DatarateChannel, DatarateChannelMetrics},
    runtime::Builder,
};
use serial_test::serial;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::{
    interface::{InterfaceDef, NetworkDevice},
    ioctx,
    socket::{AsRawFd, bsd_socket_info},
    tcp::{TcpListener, TcpStream},
};

#[test]
#[serial]
fn test_tcp_removes_tcb() {
    let mut sim = Sim::new(()).with_stack(crate::init);
    sim.node(
        "client",
        AsyncHandler::io(|_| async move {
            ioctx().add_interface(
                InterfaceDef::new("en0", NetworkDevice::eth())
                    .ip(Ipv4Addr::new(192, 168, 2, 100).into()),
            )?;

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
        AsyncHandler::io(|_| async move {
            ioctx().add_interface(
                InterfaceDef::new("en0", NetworkDevice::eth())
                    .ip(Ipv4Addr::new(192, 168, 2, 200).into()),
            )?;

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

    a.connect_with(
        b,
        Some(DatarateChannel::new(DatarateChannelMetrics::new(
            8000000,
            Duration::from_millis(20),
            Duration::ZERO,
            ChannelDropBehaviour::Queue(None),
        ))),
    );

    let rt = Builder::seeded(123).build(sim.freeze());
    let _ = rt.run().assert_no_err();
}
