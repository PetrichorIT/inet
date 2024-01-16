use des::{
    net::{AsyncBuilder, NodeCfg},
    prelude::*,
    time::sleep,
};
use inet::{
    interface::{add_interface, Interface, NetworkDevice},
    *,
};

#[test]
#[serial_test::serial]
fn udp_ping_pong() {
    inet::init();

    des::tracing::Subscriber::default().init().unwrap();

    let mut sim = AsyncBuilder::new();
    sim.set_default_cfg(NodeCfg { join: true });
    sim.node("ping", |mut rx| async move {
        let out = std::iter::repeat_with(|| random())
            .take(4098)
            .collect::<Vec<_>>();
        let mut echoed = Vec::<u8>::with_capacity(4098);

        add_interface(Interface::ethv4_named(
            "en0",
            NetworkDevice::eth(),
            Ipv4Addr::new(192, 168, 0, 1),
            Ipv4Addr::new(255, 255, 255, 0),
        ))
        .unwrap();

        sleep(Duration::from_secs(1)).await;

        let socket = UdpSocket::bind("0.0.0.0:100").await.unwrap();
        socket.connect("192.168.0.2:200").await.unwrap();

        let mut cursor = 0;
        let mut c = 0;
        while cursor < out.len() {
            let remaning = out.len() - cursor;
            let size = random::<usize>() % (1024.min(remaning));
            let size = size.max(256).min(remaning);

            socket.send(&out[cursor..(cursor + size)]).await.unwrap();
            cursor += size;

            let d = Duration::from_secs_f64(random::<f64>());
            sleep(d).await;
            c += 1;
        }

        tracing::info!("send all {c} packets");

        loop {
            if echoed.len() >= out.len() {
                break;
            }
            // Receive contents
            let mut buf = [0u8; 1024];
            let n = socket.recv(&mut buf).await.unwrap();
            echoed.extend(&buf[..n]);
        }

        assert!(rx.try_recv().is_err());
        Ok(())
    });
    sim.node("pong", |mut rx| async move {
        add_interface(Interface::ethv4_named(
            "en0",
            NetworkDevice::eth(),
            Ipv4Addr::new(192, 168, 0, 2),
            Ipv4Addr::new(255, 255, 255, 0),
        ))
        .unwrap();

        sleep(Duration::from_secs(1)).await;

        let socket = UdpSocket::bind("0.0.0.0:200").await.unwrap();
        let mut acc = 0;
        while acc < 4098 {
            let mut buf = [0u8; 1024];
            let (n, from) = socket.recv_from(&mut buf).await.unwrap();
            acc += n;
            socket.send_to(&buf[..n], from).await.unwrap();
        }

        assert!(rx.try_recv().is_err());
        Ok(())
    });
    sim.connect("ping", "pong");

    let _ = Builder::seeded(123)
        .max_time(100.0.into())
        .max_itr(1000)
        .build(sim.build())
        .run()
        .unwrap();
}
