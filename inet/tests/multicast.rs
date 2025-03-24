use des::{runtime::RuntimeError, time::sleep};
use inet::{
    interface::IfId,
    ipv6::multicast::{designate_mdl, join_multicast_group},
    test_util::SimpleSim,
};
use std::{net::Ipv6Addr, time::Duration};

#[test]
fn run() -> Result<(), RuntimeError> {
    des::tracing::init();
    let mut sim = SimpleSim::new(inet::init);

    let group: Ipv6Addr = "ff15::1".parse().unwrap();

    sim.node_require_join("fe80::1", move || async move {
        sleep(Duration::from_secs(8)).await;
        designate_mdl(IfId::new("en0"))?;

        Ok(())
    });

    sim.node_require_join("fe80::2", move || async move {
        sleep(Duration::from_secs(2)).await;
        join_multicast_group(group, None)?;
        sleep(Duration::from_secs(20)).await;

        Ok(())
    });

    // sim.node_require_join("fe80::3", move || async move {
    //     sleep(Duration::from_secs(3)).await;
    //     join_multicast_group(group, None)?;
    //     Ok(())
    // });

    sim.run()
}
