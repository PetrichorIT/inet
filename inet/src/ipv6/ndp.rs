use des::time::SimTime;
use fxhash::{FxBuildHasher, FxHashMap};
use types::{
    icmpv6::{IcmpV6NDPOption, IcmpV6NeighborAdvertisment, IcmpV6PrefixInformation},
    iface::MacAddress,
    ip::{Ipv6Packet, Ipv6Prefix},
    util::FixedBuffer,
};
use std::{collections::VecDeque, fmt, net::Ipv6Addr, ops, time::Duration};

use crate::interface::{IfId, InterfaceAddrV6};

#[derive(Debug)]
pub struct Solicitations {
    queries: FxHashMap<Ipv6Addr, QueryType>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QueryType {
    NeighborSolicitation,
    TentativeAddressCheck(InterfaceAddrV6),
}

impl Solicitations {
    pub fn new() -> Self {
        Self {
            queries: FxHashMap::with_hasher(FxBuildHasher::default()),
        }
    }

    pub fn register(&mut self, target: Ipv6Addr, typ: QueryType) {
        let entry = self.queries.insert(target, typ);
        assert!(
            entry.is_none(),
            "Doubly registered query {target}: allready existent entry {entry:?}"
        );
    }

    pub fn lookup(&self, target: Ipv6Addr) -> Option<QueryType> {
        self.queries.get(&target).cloned()
    }

    pub fn remove(&mut self, target: Ipv6Addr) {
        self.queries.remove(&target);
    }
}

#[derive(Debug, Default)]
pub struct NeighborCache {
    pub(super) mapping: FxHashMap<Ipv6Addr, NeighborCacheEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NeighborCacheEntry {
    addr: MacAddress,
    is_router: bool,
    ifid: IfId,
    expires: SimTime,
    state: NeighborCacheEntryState,
    resolution_buffer: FixedBuffer<Ipv6Packet>,
    pub number_of_sent_solicitations: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(unused)]
enum NeighborCacheEntryState {
    Incomplete,
    Reachable,
    Stale,
    Delay,
    Probe,
}

impl NeighborCache {
    pub fn add_static(&mut self, addr: Ipv6Addr, ifid: IfId, is_router: bool) {
        self.mapping.insert(
            addr,
            NeighborCacheEntry {
                addr: MacAddress::NULL,
                is_router,
                ifid,
                expires: SimTime::MAX,
                state: NeighborCacheEntryState::Stale,
                resolution_buffer: FixedBuffer::new(8),
                number_of_sent_solicitations: 0,
            },
        );
    }

    pub fn lookup(&self, ip: Ipv6Addr) -> Option<(MacAddress, IfId)> {
        if ip.is_multicast() {
            return Some((MacAddress::ipv6_multicast(ip), IfId::NULL));
        }

        let entry = self.mapping.get(&ip)?;
        if entry.state == NeighborCacheEntryState::Reachable {
            Some((entry.addr, entry.ifid))
        } else {
            None
        }
    }

    pub fn enqueue(&mut self, ip: Ipv6Addr, pkt: Ipv6Packet) {
        let entry = self.mapping.get_mut(&ip).unwrap();
        entry.resolution_buffer.enqueue(pkt);
    }

    pub fn dequeue(&mut self, ip: Ipv6Addr) -> VecDeque<Ipv6Packet> {
        let entry = self.mapping.get_mut(&ip).unwrap();
        entry.resolution_buffer.extract()
    }

    pub fn update(&mut self, ip: Ipv6Addr, mac: MacAddress, ifid: IfId, is_router: bool) {
        if let Some(entry) = self.mapping.get_mut(&ip) {
            entry.addr = mac;
            entry.ifid = ifid;
            entry.is_router = is_router;
            entry.expires = SimTime::now() + Duration::from_secs(30);
            tracing::trace!(IFACE = %ifid, "updated neighbor entry {ip} -> {entry}");
        } else {
            let entry = NeighborCacheEntry {
                addr: mac,
                is_router,
                ifid,
                expires: SimTime::now(),
                state: NeighborCacheEntryState::Stale,
                resolution_buffer: FixedBuffer::new(8),
                number_of_sent_solicitations: 0,
            };
            tracing::trace!(IFACE = %ifid, "created neighbor entry {ip} -> {entry}");
            self.mapping.insert(ip, entry);
        }
    }

    pub fn set_reachable(&mut self, ip: Ipv6Addr) {
        let entry = self.mapping.get_mut(&ip).unwrap();
        entry.state = NeighborCacheEntryState::Reachable;
    }

    pub fn set_stale(&mut self, ip: Ipv6Addr) {
        let entry = self.mapping.get_mut(&ip).unwrap();
        entry.state = NeighborCacheEntryState::Stale;
    }

    /// returns whether another request should be send
    pub fn record_timeout(&mut self, addr: Ipv6Addr) -> Option<usize> {
        let entry = self.mapping.get_mut(&addr)?;
        entry.number_of_sent_solicitations += 1;
        Some(entry.number_of_sent_solicitations)
    }

    pub fn initalize(&mut self, ip: Ipv6Addr, ifid: IfId) {
        self.mapping.insert(
            ip,
            NeighborCacheEntry {
                addr: MacAddress::NULL,
                is_router: false,
                ifid,
                expires: SimTime::MAX,
                state: NeighborCacheEntryState::Incomplete,
                resolution_buffer: FixedBuffer::new(8),
                number_of_sent_solicitations: 1,
            },
        );
    }

    /// Returns whether to empty the buckets elements
    pub fn process(
        &mut self,
        ifid: IfId,
        adv: &IcmpV6NeighborAdvertisment,
        default_router_list: &mut DefaultRouterList,
    ) -> bool {
        let Some(entry) = self.mapping.get_mut(&adv.target) else {
            return false;
        };

        let target_ll = adv.options.iter().find_map(|opt| {
            if let IcmpV6NDPOption::TargetLinkLayerAddress(mac) = opt {
                Some(*mac)
            } else {
                None
            }
        });

        match entry.state {
            NeighborCacheEntryState::Incomplete => {
                let Some(target_ll) = target_ll else {
                    return false;
                };

                entry.number_of_sent_solicitations = 0;
                if adv.solicited {
                    entry.state = NeighborCacheEntryState::Reachable;
                } else {
                    entry.state = NeighborCacheEntryState::Stale;
                };
                self.update(adv.target, target_ll, ifid, adv.router);

                true
            }
            state if !adv.overide => {
                if state == NeighborCacheEntryState::Reachable {
                    entry.state = NeighborCacheEntryState::Stale;
                }
                tracing::warn!("want to process, some override stuff");
                false
            }
            _state if adv.overide => {
                let mut updated = false;
                if let Some(target_ll) = target_ll {
                    entry.addr = target_ll;
                    updated = true;
                    // TODO: UPDATE NESSECARY
                }
                if adv.solicited {
                    entry.state = NeighborCacheEntryState::Reachable;
                } else if updated {
                    entry.state = NeighborCacheEntryState::Stale;
                }

                let prev = entry.is_router;
                entry.is_router = adv.router;

                if prev && !adv.router {
                    default_router_list.remove(adv.target);
                }

                true
            }
            _ => {
                tracing::warn!("want to process, def else");
                false
            }
        }
    }

    pub fn set_router(&mut self, ip: Ipv6Addr) {
        if let Some(entry) = self.mapping.get_mut(&ip) {
            entry.is_router = true;
        }
    }

    pub fn remove(&mut self, target: Ipv6Addr) {
        self.mapping.remove(&target);
    }
}

impl fmt::Display for NeighborCacheEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {}on {} ({:?})",
            self.addr,
            if self.is_router { "#router " } else { "" },
            self.ifid,
            self.state
        )
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct DestinationCache {
    pub(super) mapping: FxHashMap<Ipv6Addr, DestinationCacheEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DestinationCacheEntry {
    pub next_hop: Ipv6Addr,
    pub path_mtu: usize,
    expires: SimTime,
    // RTT TIMERS ?
}

impl DestinationCache {
    pub fn set(&mut self, dst: Ipv6Addr, next_hop: Ipv6Addr) {
        let entry = self
            .mapping
            .entry(dst)
            .or_insert_with(|| DestinationCacheEntry {
                next_hop,
                path_mtu: usize::MAX,
                expires: SimTime::now(),
            });
        entry.next_hop = next_hop;
        entry.expires = SimTime::now();
    }

    pub fn lookup(&mut self, ip: Ipv6Addr, neighbor_cache: &NeighborCache) -> Option<Ipv6Addr> {
        if ip.is_multicast() {
            return Some(ip);
        }

        self.mapping
            .get(&ip)
            .map(|entry| entry.next_hop)
            .or_else(|| {
                if neighbor_cache.mapping.contains_key(&ip) {
                    Some(ip)
                } else {
                    None
                }
            })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrefixList {
    list: Vec<PrefixListEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrefixListEntry {
    pub prefix: Ipv6Prefix,
    pub assigned_addr: Option<Ipv6Addr>,
    expires: SimTime,
    addr_auto_cfg: bool,
}

impl PrefixList {
    pub fn new() -> Self {
        PrefixList {
            list: vec![PrefixListEntry {
                prefix: Ipv6Prefix::LINK_LOCAL,
                assigned_addr: None,
                expires: SimTime::MAX,
                addr_auto_cfg: false,
            }],
        }
    }

    pub fn sort(&mut self) {
        self.list
            .sort_by(|l, r| r.prefix.len().cmp(&l.prefix.len()))
    }

    pub fn next_hop_determination(&self, dst: Ipv6Addr) -> Option<Ipv6Addr> {
        for entry in &self.list {
            if entry.matches_dst(dst) {
                return Some(dst);
            }
        }
        None
    }

    pub fn assign(&mut self, info: &IcmpV6PrefixInformation, addr: Ipv6Addr) {
        if let Some(entry) = self
            .list
            .iter_mut()
            .find(|entry| entry.prefix == (info.prefix, info.prefix_len))
        {
            entry.assigned_addr = Some(addr)
        }
    }

    /// Rreturns whether a new address should be autocfged
    pub fn update(&mut self, info: &IcmpV6PrefixInformation) -> bool {
        if let Some(entry) = self
            .list
            .iter_mut()
            .find(|entry| entry.prefix == (info.prefix, info.prefix_len))
        {
            entry.expires = SimTime::now() + Duration::from_millis(info.preferred_lifetime as u64);
            self.timeout();
            false
        } else {
            if info.valid_lifetime != 0 {
                self.list.push(PrefixListEntry {
                    prefix: Ipv6Prefix::new(info.prefix, info.prefix_len),
                    assigned_addr: None,
                    expires: SimTime::now() + Duration::from_millis(info.preferred_lifetime as u64),
                    addr_auto_cfg: info.autonomous_address_configuration,
                });
                self.sort();
                info.autonomous_address_configuration
            } else {
                /* silent ignore */
                false
            }
        }
    }

    pub fn timeout_for(&self, info: &IcmpV6PrefixInformation) -> Option<SimTime> {
        self.list
            .iter()
            .find(|v| v.prefix == Ipv6Prefix::new(info.prefix, info.prefix_len))
            .map(|e| e.expires)
    }

    pub fn set_static(&mut self, prefix: Ipv6Prefix) {
        self.list.push(PrefixListEntry {
            prefix,
            assigned_addr: None,
            expires: SimTime::MAX,
            addr_auto_cfg: false,
        });
        self.sort();
    }

    pub fn timeout(&mut self) -> Vec<PrefixListEntry> {
        let mut removed = Vec::new();
        let mut i = 0;
        while i < self.list.len() {
            if self.list[i].expires > SimTime::now() {
                i += 1;
            } else {
                removed.push(self.list.remove(i));
            }
        }
        removed
    }
}

impl PrefixListEntry {
    pub fn matches_dst(&self, addr: Ipv6Addr) -> bool {
        self.prefix.contains(addr)
    }
}

impl ops::Deref for PrefixList {
    type Target = [PrefixListEntry];
    fn deref(&self) -> &Self::Target {
        &self.list
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DefaultRouterList {
    pub list: Vec<DefaultRouterListEntry>,
    next_timeout: SimTime,
    ptr: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DefaultRouterListEntry {
    pub addr: Ipv6Addr,
    expires: SimTime,
}

impl DefaultRouterList {
    pub fn new() -> Self {
        DefaultRouterList {
            list: Vec::new(),
            next_timeout: SimTime::MAX,
            ptr: 0,
        }
    }

    pub fn next_router(&mut self, neighbor_cache: &NeighborCache) -> Option<Ipv6Addr> {
        for _ in 0..self.list.len() {
            let router = &self.list[self.ptr];
            let Some(entry) = neighbor_cache.mapping.get(&router.addr) else {
                tracing::warn!("inconsistency in ipv6 tables");
                continue;
            };

            match entry.state {
                NeighborCacheEntryState::Reachable => return Some(router.addr),
                NeighborCacheEntryState::Stale => return Some(router.addr),
                _ => {}
            }
        }
        None
    }

    pub fn update(&mut self, ip: Ipv6Addr, lifetime: Duration) {
        if let Some(entry) = self.list.iter_mut().find(|r| r.addr == ip) {
            entry.expires = SimTime::now() + lifetime;
            self.next_timeout = self.next_timeout.min(entry.expires);

            self.list.sort_by(|l, r| l.expires.cmp(&r.expires)); // Not nessecary but nice
            self.timeout();
        } else if lifetime != Duration::ZERO {
            let entry = DefaultRouterListEntry {
                addr: ip,
                expires: SimTime::now() + lifetime,
            };
            self.next_timeout = self.next_timeout.min(entry.expires);
            self.list.push(entry);
        }
    }

    pub fn remove(&mut self, ip: Ipv6Addr) {
        self.list.retain(|entry| entry.addr != ip)
    }

    pub fn timeout(&mut self) {
        self.list.retain(|entry| entry.expires > SimTime::now())
    }
}
