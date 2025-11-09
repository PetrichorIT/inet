use std::{
    net::{IpAddr, Ipv6Addr},
    time::Duration,
};

use des::{runtime::RuntimeError, time::sleep};
use serial_test::serial;

use crate::{
    dns::lookup_host,
    interface::NetworkDevice,
    ioctx,
    ipv6::{router, socket::RawV6Socket},
    utils::SimpleSim,
    utils::{NetstatConnection, NetstatConnectionProto},
};

fn as_ipv6(ip: IpAddr) -> Ipv6Addr {
    match ip {
        IpAddr::V6(v6) => v6,
        _ => panic!("not allowed"),
    }
}

#[test]
#[serial]
fn repr_as_bsd_sockets() -> Result<(), RuntimeError> {
    let mut sim = SimpleSim::default();
    sim.node_require_join("fe80::abcd", || async move {
        let sock1 = RawV6Socket::new(42)?;
        let sock2 = RawV6Socket::new(78)?;
        sock1.connect("200a:a:a::1234".parse().unwrap())?;
        sock2.bind("fe80::abcd".parse().unwrap())?;

        let sockets = crate::utils::netstat()?;
        assert_eq!(sockets.active_connections.len(), 2);
        assert_eq!(
            sockets.active_connections[0],
            NetstatConnection {
                proto: NetstatConnectionProto::Raw6,
                local_addr: "[::]:0".parse().unwrap(),
                foreign_addr: "[200a:a:a::1234]:0".parse().unwrap(),
                send_q: 0,
                recv_q: 0,
                state: None
            },
        );
        assert_eq!(
            sockets.active_connections[1],
            NetstatConnection {
                proto: NetstatConnectionProto::Raw6,
                local_addr: "[fe80::abcd]:0".parse().unwrap(),
                foreign_addr: "[::]:0".parse().unwrap(),
                send_q: 0,
                recv_q: 0,
                state: None
            },
        );

        drop((sock1, sock2));

        let sockets = crate::utils::netstat()?;
        assert_eq!(sockets.active_connections.len(), 0);

        Ok(())
    });

    sim.run()
}

#[test]
#[serial]
fn bound_socket_is_selective() -> Result<(), RuntimeError> {
    // des::tracing::init();

    let mut sim = SimpleSim::default();
    sim.v6 = true;
    sim.node_require_join("receiver", || async move {
        let mut handle = ioctx().get_interface("en0")?;
        handle.wait_for_global().await;
        let link_local = handle.status().addrs.v6.addrs().next().unwrap();

        let mut sock = RawV6Socket::new(42)?;
        sock.bind(link_local)?;
        assert_eq!(&sock.recv().await?.content[..], &[1, 2, 3]);
        assert_eq!(&sock.recv().await?.content[..], &[4, 5, 6]);
        assert_eq!(&sock.recv().await?.content[..], &[7, 8, 9]);
        Ok(())
    });

    sim.node_require_join("sender", || async move {
        ioctx().get_interface("en0")?.wait_for_global().await;

        // prevent races
        sleep(Duration::from_secs(1)).await;

        let addrs = lookup_host(("receiver", 0)).await?.collect::<Vec<_>>();
        assert_eq!(addrs.len(), 2);
        let link_local = as_ipv6(addrs[0].ip());
        let global = as_ipv6(addrs[1].ip());

        let mut sock = RawV6Socket::new(42)?;
        sock.bind(Ipv6Addr::UNSPECIFIED)?; // < TODO this should not be required
        sock.send_to(&[1, 2, 3], link_local).await?;
        sock.send_to(&[0, 0, 0], global).await?;
        sock.send_to(&[4, 5, 6], link_local).await?;
        sock.send_to(&[7, 8, 9], link_local).await?;

        Ok(())
    });

    sim.raw("router", |_| async move {
        router::declare_router()?;
        router::add_routing_interface(
            "lan0",
            NetworkDevice::eth(),
            &["2003:a:b::1".parse().unwrap()],
            true,
        )?;
        router::add_routing_prefix("lan0", "2003:a:b::/64".parse().unwrap())?;
        Ok(())
    });

    sim.run()
}
