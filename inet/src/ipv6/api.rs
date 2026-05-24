use std::{io, net::Ipv6Addr};

use fxhash::FxHashMap;

use crate::{
    IOHandle, ioctx,
    ipv6::ndp::{
        DefaultRouterListEntry, DestinationCacheEntry, NeighborCacheEntry, PrefixListEntry,
    },
};

use super::cfg::HostConfiguration;

pub fn set_node_cfg(cfg: HostConfiguration) -> io::Result<()> {
    ioctx().ipv6_set_node_cfg(cfg)
}

#[derive(Debug, Clone, PartialEq)]
pub struct Ipv6Status {
    pub prefixes: Vec<PrefixListEntry>,
    pub destinations: FxHashMap<Ipv6Addr, DestinationCacheEntry>,
    pub routers: Vec<DefaultRouterListEntry>,
    pub neighbors: FxHashMap<Ipv6Addr, NeighborCacheEntry>,
}

pub fn ipv6() {
    ioctx().ipv6_info();
}

impl IOHandle {
    pub fn ipv6_set_node_cfg(&self, cfg: HostConfiguration) -> io::Result<()> {
        self.do_mutating_on_active_module(|ctx| {
            ctx.ipv6.cfg = cfg;
            Ok(())
        })
    }

    pub fn ipv6_info(&self) -> Ipv6Status {
        self.do_mutating(|ctx| Ipv6Status {
            prefixes: ctx.ipv6.prefixes.iter().cloned().collect(),
            destinations: ctx.ipv6.destinations.mapping.clone(),
            routers: ctx.ipv6.default_routers.list.clone(),
            neighbors: ctx.ipv6.neighbors.mapping.clone(),
        })
    }
}
