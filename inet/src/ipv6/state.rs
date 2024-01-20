use std::{fmt, net::Ipv6Addr, time::Duration};

use des::time::SimTime;
use fxhash::FxHashMap;
use inet_types::{
    icmpv6::{IcmpV6NDPOption, IcmpV6NeighborAdvertisment, IcmpV6PrefixInformation},
    iface::MacAddress,
    ip::Ipv6Packet,
};

use crate::interface::IfId;

pub struct InterfaceState {
    pub link_mtu: u32,
    pub cur_hop_limit: u8,
    pub base_reachable_time: Duration,
    pub reachable_time: Duration,
    pub retrans_timer: Duration,
}

#[derive(Debug, Default)]
pub struct NeighborCache {
    mapping: FxHashMap<Ipv6Addr, NeighborCacheEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NeighborCacheEntry {
    addr: MacAddress,
    is_router: bool,
    ifid: IfId,
    expires: SimTime,
    state: NeighborCacheEntryState,
    resolution_buffer: Vec<Ipv6Packet>,
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
    pub fn update(&mut self, ip: Ipv6Addr, mac: MacAddress, ifid: IfId, is_router: bool) {
        if let Some(entry) = self.mapping.get_mut(&ip) {
            entry.addr = mac;
            entry.ifid = ifid;
            entry.is_router = is_router;
            entry.expires = SimTime::now() + Duration::from_secs(30);
            tracing::trace!(IP = %ip, "updated neighbor entry {entry}");
        } else {
            let entry = NeighborCacheEntry {
                addr: mac,
                is_router,
                ifid,
                expires: SimTime::now(),
                state: NeighborCacheEntryState::Stale,
                resolution_buffer: Vec::with_capacity(8),
            };
            tracing::trace!(IP = %ip, "created neighbor entry {entry}");
            self.mapping.insert(ip, entry);
        }
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
                resolution_buffer: Vec::with_capacity(8),
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
            _ => false,
        }
    }

    pub fn set_router(&mut self, ip: Ipv6Addr) {
        if let Some(entry) = self.mapping.get_mut(&ip) {
            entry.is_router = true;
        }
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
    mapping: FxHashMap<Ipv6Addr, DestinationCacheEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DestinationCacheEntry {
    on_link: bool,
    next_hop: Ipv6Addr,
    path_mtu: usize,
    // RTT TIMERS ?
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct PrefixList {
    list: Vec<PrefixListEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PrefixListEntry {
    prefix: Ipv6Addr,
    prefix_len: u8,
    expires: SimTime,
    addr_auto_cfg: bool,
}

impl PrefixList {
    /// Rreturns whether a new address should be autocfged
    pub fn update(&mut self, info: &IcmpV6PrefixInformation) -> bool {
        if let Some(entry) = self
            .list
            .iter_mut()
            .find(|entry| entry.prefix == info.prefix && entry.prefix_len == info.prefix_len)
        {
            entry.expires = SimTime::now() + Duration::from_millis(info.preferred_lifetime as u64);
            self.timeout();
            false
        } else {
            if info.valid_lifetime != 0 {
                self.list.push(PrefixListEntry {
                    prefix: info.prefix,
                    prefix_len: info.prefix_len,
                    expires: SimTime::now() + Duration::from_millis(info.preferred_lifetime as u64),
                    addr_auto_cfg: info.autonomous_address_configuration,
                });

                info.autonomous_address_configuration
            } else {
                /* silent ignore */
                false
            }
        }
    }

    pub fn timeout(&mut self) {
        self.list.retain(|entry| entry.expires > SimTime::now())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DefaultRouterList {
    list: Vec<DefaultRouterListEntry>,
    next_timeout: SimTime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DefaultRouterListEntry {
    router: Ipv6Addr,
    expires: SimTime,
}

impl DefaultRouterList {
    pub fn new() -> Self {
        DefaultRouterList {
            list: Vec::new(),
            next_timeout: SimTime::MAX,
        }
    }

    pub fn update(&mut self, ip: Ipv6Addr, lifetime: Duration) {
        if let Some(entry) = self.list.iter_mut().find(|r| r.router == ip) {
            entry.expires = SimTime::now() + lifetime;
            self.next_timeout = self.next_timeout.min(entry.expires);

            self.list.sort_by(|l, r| l.expires.cmp(&r.expires)); // Not nessecary but nice
            self.timeout();
        } else if lifetime != Duration::ZERO {
            let entry = DefaultRouterListEntry {
                router: ip,
                expires: SimTime::now() + lifetime,
            };
            self.next_timeout = self.next_timeout.min(entry.expires);
            self.list.push(entry);
        }
    }

    pub fn remove(&mut self, ip: Ipv6Addr) {
        self.list.retain(|entry| entry.router != ip)
    }

    pub fn timeout(&mut self) {
        self.list.retain(|entry| entry.expires > SimTime::now())
    }
}
