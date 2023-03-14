use crate::{interface::IfId, ip::ipv6_matches_subnet};
use des::time::SimTime;
use std::net::Ipv6Addr;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Ipv6RoutingTable {
    pub(super) entries: Vec<Entry>,
}

type Entry = Ipv6RoutingTableEntry;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Ipv6RoutingTableEntry {
    pub(super) addr: Ipv6Addr,
    pub(super) mask: Ipv6Addr,

    pub(super) gateway: Ipv6Gateway,
    pub(super) iface: IfId,
    pub(super) expire: SimTime,
    pub(super) prio: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Ipv6Gateway {
    Local,
    Broadcast,
    Gateway(Ipv6Addr),
}

impl Ipv6RoutingTable {
    pub fn new() -> Ipv6RoutingTable {
        Self {
            entries: Vec::new(),
        }
    }

    pub fn add_entry(
        &mut self,
        addr: Ipv6Addr,
        mask: Ipv6Addr,
        gateway: Ipv6Gateway,
        iface: IfId,
        prio: usize,
    ) {
        assert!(prio > 0, "entry priority 0 is reserved for internal use");
        let entry = Entry {
            addr,
            mask,
            gateway,
            iface,
            expire: SimTime::MAX,
            prio,
        };
        match self.entries.binary_search_by(|a| a.prio.cmp(&entry.prio)) {
            Ok(i) | Err(i) => self.entries.insert(i, entry),
        }
    }

    pub fn loopuk_gateway(&self, dest: Ipv6Addr) -> Option<(&Ipv6Gateway, &IfId)> {
        let now = SimTime::now();

        let mut state = 0;
        let mut result = None;
        let mut result_prefixlen = 0;

        for i in 0..self.entries.len() {
            if ipv6_matches_subnet(dest, self.entries[i].addr, self.entries[i].mask)
                && self.entries[i].expire > now
            {
                // (0) Valid entry found.
                state = self.entries[i].prio;
                if result.is_some() {
                    if result_prefixlen > prefixlen(self.entries[i].mask) {
                        continue;
                    }
                }
                result = Some((&self.entries[i].gateway, &self.entries[i].iface));
                result_prefixlen = prefixlen(self.entries[i].mask);
            } else if state != 0 && self.entries[i].prio > state {
                // (1) Valid entry was found, but no longer valid.
                return result;
            }
        }

        result
    }
}

fn prefixlen(ip: Ipv6Addr) -> u32 {
    u128::from_be_bytes(ip.octets()).leading_ones()
}
