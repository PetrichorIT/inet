use std::time::Duration;

use des::{runtime::RuntimeError, time::sleep};
use serial_test::serial;

use crate::{
    interface::IfId,
    ipv6::multicast::{designate_mdl, join_multicast_group, leave_multicast_group, GroupState},
    test_util::SimpleSim,
};

use super::*;

#[test]
#[serial]
fn host_unsolicited_report() -> Result<(), RuntimeError> {
    let mut sim = SimpleSim::new(crate::init);
    sim.node_require_join("fe80::1", || async move {
        designate_mdl(IfId::new("en0"))?;
        sleep(Duration::from_secs(90)).await;
        assert_multicast_groups_are("en0", &["ff02::1:ff00:1", "ff02::1:ff00:2", "ff15::6"]);
        Ok(())
    });

    sim.node("fe80::2", || async move {
        sleep(Duration::from_secs(80)).await;
        join_multicast_group("ff15::6".parse().unwrap(), None)?;

        Ok(())
    });
    sim.run_max_time(200.0.into())
}

#[test]
#[serial]
fn host_leave_scope_ends_group() -> Result<(), RuntimeError> {
    let mut sim = SimpleSim::new(crate::init);
    sim.node_require_join("fe80::1", || async move {
        designate_mdl(IfId::new("en0"))?;

        sleep(Duration::from_secs(50)).await;
        assert_multicast_groups_are("en0", &["ff02::1:ff00:1", "ff02::1:ff00:2", "ff15::6"]);

        sleep(Duration::from_secs(31)).await;
        assert_multicast_group_state("en0", "ff15::6", GroupState::CheckingListeners);

        sleep(Duration::from_secs(10)).await;
        assert_multicast_groups_are("en0", &["ff02::1:ff00:1", "ff02::1:ff00:2"]);
        assert_multicast_group_state("en0", "ff15::6", GroupState::NoListenersPresent);
        Ok(())
    });

    sim.node("fe80::2", || async move {
        join_multicast_group("ff15::6".parse().unwrap(), None)?;
        sleep(Duration::from_secs(80)).await;
        leave_multicast_group("ff15::6".parse().unwrap())?;

        Ok(())
    });
    sim.run_max_time(200.0.into())
}

#[test]
#[serial]
fn host_leave_scope_group_remains() -> Result<(), RuntimeError> {
    let mut sim = SimpleSim::new(crate::init);
    sim.node_require_join("fe80::1", || async move {
        designate_mdl(IfId::new("en0"))?;

        sleep(Duration::from_secs(50)).await;
        assert_multicast_groups_are(
            "en0",
            &[
                "ff02::1:ff00:1",
                "ff02::1:ff00:2",
                "ff02::1:ff00:3",
                "ff15::6",
            ],
        );

        sleep(Duration::from_secs(31)).await;
        // assert_multicast_group_state("en0", "ff15::6", GroupState::CheckingListeners);
        // -> can not be sure, since flag might be unset on fe80::2 so no done might be sent

        sleep(Duration::from_secs(40)).await;
        assert_multicast_groups_are(
            "en0",
            &[
                "ff02::1:ff00:1",
                "ff02::1:ff00:2",
                "ff02::1:ff00:3",
                "ff15::6",
            ],
        );
        assert_multicast_group_state("en0", "ff15::6", GroupState::ListenersPresent);
        Ok(())
    });

    sim.node("fe80::2", || async move {
        join_multicast_group("ff15::6".parse().unwrap(), None)?;
        sleep(Duration::from_secs(80)).await;
        leave_multicast_group("ff15::6".parse().unwrap())?;

        Ok(())
    });

    sim.node("fe80::3", || async move {
        join_multicast_group("ff15::6".parse().unwrap(), None)?;
        Ok(())
    });

    sim.run_max_time(200.0.into())
}
