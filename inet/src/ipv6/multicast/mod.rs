//! Multicast managment contains two components:
//!
//! - Joined multicast listening groups (hosts)
//! - Required multicast groups for subnet (router)

use crate::{interface::IfId, IOContext};
use fxhash::{FxBuildHasher, FxHashMap};
use std::{io, net::Ipv6Addr};
use types::{
    icmpv6::IcmpV6MulticastListenerMessage,
    ip::{Ipv6AddrExt, Ipv6AddrScope, Ipv6Packet},
};

mod discovery_host;
mod discovery_router;

pub use discovery_host::*;
pub use discovery_router::*;

pub fn join_multicast_group(addr: Ipv6Addr, ifid: Option<IfId>) -> io::Result<()> {
    IOContext::failable_api(|ctx| ctx.ipv6_join_multicast_group(addr, ifid))
}

pub fn leave_multicast_group(addr: Ipv6Addr) -> io::Result<()> {
    IOContext::failable_api(|ctx| ctx.ipv6_leave_multicast_group(addr))
}

pub fn designate_mdl(ifid: IfId) -> io::Result<()> {
    IOContext::failable_api(|ctx| ctx.designate_ipv6_mld_querier(ifid))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MulticastListenerDiscoveryCtrl {
    pub querier: Option<RouterState>,
    pub group_memberships: FxHashMap<Ipv6Addr, NodeState>,
}

impl Default for MulticastListenerDiscoveryCtrl {
    fn default() -> Self {
        Self {
            querier: None,
            group_memberships: FxHashMap::with_hasher(FxBuildHasher::default()),
        }
    }
}

impl IOContext {
    pub fn ipv6_join_multicast_group(
        &mut self,
        addr: Ipv6Addr,
        ifid: Option<IfId>,
    ) -> io::Result<()> {
        assert!(addr.is_multicast());

        // Select an appropiate interface, based on the v6 capability
        let ifid = match ifid {
            Some(ifid) => ifid,
            None => self
                .ifaces
                .values()
                .find_map(|iface| iface.flags.v6.then(|| iface.name.id()))
                .ok_or(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "could not find capable iface",
                ))?,
        };

        let iface = self.get_mut_iface(ifid)?;
        iface.bindings.v6.join(addr);

        self.mld_on_event(ifid, NodeEvent::StartListening, addr)
    }

    pub fn ipv6_leave_multicast_group(&mut self, addr: Ipv6Addr) -> io::Result<()> {
        assert!(addr.is_multicast());
        for id in self
            .ifaces
            .values()
            .filter(|iface| iface.bindings.v6.multicast.contains(&addr))
            .map(|iface| iface.name.id())
            .collect::<Vec<_>>()
        {
            self.mld_on_event(id, NodeEvent::StopListening, addr)?;
            let iface = self.get_mut_iface(id)?;
            iface.bindings.v6.leave(addr);
        }
        Ok(())
    }

    pub fn ipv6_icmp_recv_multicast_listener_query(
        &mut self,
        _pkt: &Ipv6Packet,
        ifid: IfId,
        query: IcmpV6MulticastListenerMessage,
    ) -> io::Result<bool> {
        let general_query = query.multicast_addr == Ipv6Addr::UNSPECIFIED;
        if general_query {
            // When a node receives a General Query, it sets a delay timer for each
            // multicast address to which it is listening on the interface from
            // which it received the Query, EXCLUDING the link-scope all-nodes
            // address and any multicast addresses of scope 0 (reserved) or 1
            // (node-local)....

            let addrs = self
                .ifaces
                .get(&ifid)
                .expect("unknow interface")
                .bindings
                .multicast_scopes()
                .into_iter()
                .filter(|addr| addr.scope() > Ipv6AddrScope::InterfaceLocal) // only with great scopes
                .filter(|addr| **addr != Ipv6Addr::MULTICAST_ALL_NODES)
                .copied()
                .collect::<Vec<_>>();

            for addr in addrs {
                self.mld_on_event(ifid, NodeEvent::QueryReceived(query.clone()), addr)?;
            }
        } else {
            assert!(query.multicast_addr.is_multicast());
            let addr = query.multicast_addr;
            self.mld_on_event(ifid, NodeEvent::QueryReceived(query), addr)?;
        }

        Ok(true)
    }

    pub fn ipv6_icmp_recv_multicast_listener_discovery_report(
        &mut self,
        _ip: &Ipv6Packet,
        ifid: IfId,
        report: IcmpV6MulticastListenerMessage,
    ) -> io::Result<bool> {
        let addr = report.multicast_addr;
        self.mld_querier_on_event(
            ifid,
            RouterEvent::GroupEvent(report.multicast_addr, GroupEvent::ReportRecevied),
        )?;
        self.mld_on_event(ifid, NodeEvent::ReportReceived(report), addr)?;
        Ok(true)
    }

    pub fn ipv6_icmp_recv_multicast_listener_discovery_done(
        &mut self,
        _ip: &Ipv6Packet,
        ifid: IfId,
        report: IcmpV6MulticastListenerMessage,
    ) -> io::Result<bool> {
        self.mld_querier_on_event(
            ifid,
            RouterEvent::GroupEvent(report.multicast_addr, GroupEvent::DoneReceived),
        )?;
        Ok(true)
    }
}
