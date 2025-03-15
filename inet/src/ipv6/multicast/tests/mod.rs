use fxhash::FxHashSet;

use super::{GroupState, Role};
use crate::{interface::IfId, ipv6::multicast::NodeState, IOContext};
use std::net::Ipv6Addr;

mod host;
mod querier;
mod udp;

fn assert_memberships_are(iface: &str, slice: &[&str]) {
    IOContext::with_current(|ctx| {
        let ctrl = ctx.ipv6.mld.get(&IfId::new(iface)).unwrap();
        assert_eq!(
            ctrl.memberships
                .iter()
                .filter(|v| *v.1 != NodeState::NonListener)
                .map(|v| *v.0)
                .collect::<FxHashSet<_>>(),
            slice
                .iter()
                .map(|&s| s.parse::<Ipv6Addr>().unwrap())
                .collect()
        );
    });
}

fn assert_multicast_groups_are(iface: &str, slice: &[&str]) {
    IOContext::with_current(|ctx| {
        let ctrl = ctx.ipv6.mld.get(&IfId::new(iface)).unwrap();
        assert_eq!(
            ctrl.querier
                .as_ref()
                .map_or(FxHashSet::default(), |v| v.groups()),
            slice
                .iter()
                .map(|&s| s.parse::<Ipv6Addr>().unwrap())
                .collect()
        );
    });
}

fn assert_multicast_role(iface: &str, role: Option<Role>) {
    IOContext::with_current(|ctx| {
        let ctrl = ctx.ipv6.mld.get(&IfId::new(iface)).unwrap();
        assert_eq!(ctrl.querier.as_ref().map(|v| v.role), role);
    });
}

fn assert_multicast_group_state(iface: &str, addr: &str, state: GroupState) {
    IOContext::with_current(|ctx| {
        let ctrl = ctx.ipv6.mld.get(&IfId::new(iface)).unwrap();
        let group = ctrl
            .querier
            .as_ref()
            .expect("no active querier")
            .groups
            .get(&addr.parse().unwrap())
            .expect("group not found");
        assert_eq!(*group, state);
    });
}
