use std::{net::Ipv6Addr, time::Duration};

use des::{runtime::RuntimeError, time::sleep};
use serial_test::serial;

use crate::{UdpSocket, ipv6::multicast::tests::assert_memberships_are, test_util::SimpleSim};

#[test]
#[serial]
fn udp_can_receive_site_local_multicast() -> Result<(), RuntimeError> {
    let mut sim = SimpleSim::default();
    sim.v6 = true;
    let group = "ff15::1234".parse().unwrap();

    sim.node_require_join("alice", move || async move {
        let sock = UdpSocket::bind(":::4000").await?;
        sock.join_multicast_v6(group, None)?;

        let mut buf = [0; 100];
        let (n, from) = sock.recv_from(&mut buf).await?;
        assert_eq!(&buf[..n], b"Hello World!");
        assert_eq!(from.ip(), "fe80::30".parse::<Ipv6Addr>().unwrap());

        Ok(())
    });

    sim.node_require_join("fe80::30", move || async move {
        let sock = UdpSocket::bind(":::4000").await?;
        sock.send_to(b"Hello World!", (group, 4000)).await?;

        Ok(())
    });

    sim.run()
}

#[test]
#[serial]
fn udp_leaves_group_at_drop() -> Result<(), RuntimeError> {
    let mut sim = SimpleSim::default();
    sim.v6 = true;
    let group = "ff15::1234".parse().unwrap();

    sim.node_require_join("alice", move || async move {
        let sock = UdpSocket::bind(":::4000").await?;
        sock.join_multicast_v6(group, None)?;

        let mut buf = [0; 100];
        let (n, from) = sock.recv_from(&mut buf).await?;
        assert_eq!(&buf[..n], b"Hello World!");
        assert_eq!(from.ip(), "fe80::30".parse::<Ipv6Addr>().unwrap());
        assert_memberships_are("en0", &["ff02::1:ff00:1", &group.to_string()]);

        drop(sock);

        sleep(Duration::from_secs(10)).await;

        assert_memberships_are("en0", &["ff02::1:ff00:1"]);

        Ok(())
    });

    sim.node_require_join("fe80::30", move || async move {
        let sock = UdpSocket::bind(":::4000").await?;
        sock.send_to(b"Hello World!", (group, 4000)).await?;

        Ok(())
    });

    sim.run()
}
