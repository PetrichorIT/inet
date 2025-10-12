use std::time::Duration;

use bytes_io::FromBytes;
use des::{
    runtime::RuntimeError,
    time::{SimTime, sleep},
};
use serial_test::serial;
use types::{
    icmpv6::{IcmpV6MulticastListenerMessage, IcmpV6Packet},
    ip::{Ipv6AddrExt, Ipv6Packet},
};

use crate::{
    interface::IfId,
    ipv6::multicast::{QUERY_RESPONSE_INTERVAL, designate_mdl, undesignate_mdl},
    test_util::SimpleSim,
};

use super::*;

#[test]
#[serial]
fn detect_other_querier() -> Result<(), RuntimeError> {
    let mut sim = SimpleSim::default();
    sim.node_require_join("fe80::1", || async move {
        designate_mdl(IfId::new("en0"))?;

        sleep(Duration::from_secs(50)).await;
        assert_multicast_groups_are("en0", &["ff02::1:ff00:1", "ff02::1:ff00:2"]);
        assert_multicast_role("en0", Some(Role::Querier));

        Ok(())
    });

    sim.node("fe80::2", || async move {
        designate_mdl(IfId::new("en0"))?;

        sleep(Duration::from_secs(50)).await;
        assert_multicast_groups_are("en0", &["ff02::1:ff00:1", "ff02::1:ff00:2"]);
        assert_multicast_role("en0", Some(Role::NonQuerier));

        Ok(())
    });

    sim.run_max_time(200.0.into())
}

#[test]
#[serial]
fn other_querier_remains_in_scope() -> Result<(), RuntimeError> {
    let mut sim = SimpleSim::default();
    sim.node_require_join("fe80::1", || async move {
        designate_mdl(IfId::new("en0"))?;

        sleep(Duration::from_secs(50)).await;
        assert_multicast_groups_are("en0", &["ff02::1:ff00:1", "ff02::1:ff00:2"]);
        assert_multicast_role("en0", Some(Role::Querier));

        sleep(Duration::from_secs(300)).await;
        assert_multicast_role("en0", Some(Role::Querier));
        assert_multicast_groups_are("en0", &["ff02::1:ff00:1", "ff02::1:ff00:2"]);

        Ok(())
    });

    sim.node_require_join("fe80::2", || async move {
        designate_mdl(IfId::new("en0"))?;

        sleep(Duration::from_secs(50)).await;
        assert_multicast_groups_are("en0", &["ff02::1:ff00:1", "ff02::1:ff00:2"]);
        assert_multicast_role("en0", Some(Role::NonQuerier));

        sleep(Duration::from_secs(300)).await;
        assert_multicast_groups_are("en0", &["ff02::1:ff00:1", "ff02::1:ff00:2"]);
        assert_multicast_role("en0", Some(Role::NonQuerier));

        Ok(())
    });

    sim.run_max_time(500.0.into())
}

#[test]
#[serial]
fn other_querier_goes_out_of_scope() -> Result<(), RuntimeError> {
    let mut sim = SimpleSim::default();
    sim.node_require_join("fe80::1", || async move {
        designate_mdl(IfId::new("en0"))?;

        sleep(Duration::from_secs(50)).await;
        assert_multicast_groups_are("en0", &["ff02::1:ff00:1", "ff02::1:ff00:2"]);
        assert_multicast_role("en0", Some(Role::Querier));

        undesignate_mdl(IfId::new("en0"))?;

        sleep(Duration::from_secs(300)).await;
        assert_multicast_role("en0", None);

        Ok(())
    });

    sim.node_require_join("fe80::2", || async move {
        designate_mdl(IfId::new("en0"))?;

        sleep(Duration::from_secs(50)).await;
        assert_multicast_groups_are("en0", &["ff02::1:ff00:1", "ff02::1:ff00:2"]);
        assert_multicast_role("en0", Some(Role::NonQuerier));

        sleep(Duration::from_secs(300)).await;

        assert_multicast_groups_are("en0", &["ff02::1:ff00:1", "ff02::1:ff00:2"]);
        assert_multicast_role("en0", Some(Role::Querier));

        Ok(())
    });

    sim.run_max_time(500.0.into())
}

#[test]
#[serial]
fn sends_regular_queries() -> Result<(), RuntimeError> {
    let mut sim = SimpleSim::default();
    sim.node_require_join("fe80::1", || async move {
        designate_mdl(IfId::new("en0"))?;
        sleep(Duration::from_secs(150)).await;
        assert_multicast_groups_are("en0", &["ff02::1:ff00:1"]);
        Ok(())
    });

    sim.raw("observer", |mut rx| async move {
        assert_eq!(
            IcmpV6Packet::peek_from(
                &rx.recv()
                    .await
                    .unwrap()
                    .body
                    .content::<Ipv6Packet>()
                    .content[..]
            )?,
            IcmpV6Packet::MulticastListenerReport(IcmpV6MulticastListenerMessage {
                maximum_response_delay: Duration::ZERO,
                multicast_addr: Ipv6Addr::solicied_node_multicast("fe80::1".parse().unwrap())
            })
        );
        assert!(matches!(
            IcmpV6Packet::peek_from(
                &rx.recv()
                    .await
                    .unwrap()
                    .body
                    .content::<Ipv6Packet>()
                    .content[..]
            )?,
            IcmpV6Packet::RouterSolicitation(_)
        ));
        assert_eq!(
            IcmpV6Packet::peek_from(
                &rx.recv()
                    .await
                    .unwrap()
                    .body
                    .content::<Ipv6Packet>()
                    .content[..]
            )?,
            IcmpV6Packet::MulticastListenerQuery(IcmpV6MulticastListenerMessage {
                maximum_response_delay: QUERY_RESPONSE_INTERVAL,
                multicast_addr: Ipv6Addr::UNSPECIFIED
            })
        );
        assert_eq!(
            IcmpV6Packet::peek_from(
                &rx.recv()
                    .await
                    .unwrap()
                    .body
                    .content::<Ipv6Packet>()
                    .content[..]
            )?,
            IcmpV6Packet::MulticastListenerReport(IcmpV6MulticastListenerMessage {
                maximum_response_delay: Duration::ZERO,
                multicast_addr: Ipv6Addr::solicied_node_multicast("fe80::1".parse().unwrap())
            })
        ); // solicited ?
        assert_eq!(
            IcmpV6Packet::peek_from(
                &rx.recv()
                    .await
                    .unwrap()
                    .body
                    .content::<Ipv6Packet>()
                    .content[..]
            )?,
            IcmpV6Packet::MulticastListenerQuery(IcmpV6MulticastListenerMessage {
                maximum_response_delay: QUERY_RESPONSE_INTERVAL,
                multicast_addr: Ipv6Addr::UNSPECIFIED
            })
        );
        assert_eq!(SimTime::now().as_secs(), 125);
        Ok(())
    });

    sim.run_max_time(200.0.into())
}

#[test]
#[serial]
fn update_db_on_received_reports() -> Result<(), RuntimeError> {
    let mut sim = SimpleSim::default();
    sim.node_require_join("fe80::1", || async move {
        designate_mdl(IfId::new("en0"))?;
        sleep(Duration::from_secs(150)).await;

        assert_multicast_groups_are("en0", &["ff02::1:ff00:1", "ff02::1:ff00:2"]);
        Ok(())
    });

    sim.node("fe80::2", || async move { Ok(()) });
    sim.run_max_time(200.0.into())
}
