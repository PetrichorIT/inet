use crate::{interface::IfId, ip::ipv4_matches_subnet};
use des::time::SimTime;
use std::net::Ipv4Addr;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Ipv4RoutingTable {
    pub(super) entries: Vec<Entry>,
}

type Entry = Ipv4RoutingTableEntry;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Ipv4RoutingTableEntry {
    pub(super) addr: Ipv4Addr,
    pub(super) mask: Ipv4Addr,

    pub(super) gateway: Ipv4Gateway,
    pub(super) iface: IfId,
    pub(super) expire: SimTime,
    pub(super) prio: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Ipv4Gateway {
    Local,
    Broadcast,
    Gateway(Ipv4Addr),
}

impl Ipv4RoutingTable {
    pub fn new() -> Ipv4RoutingTable {
        Self {
            entries: Vec::new(),
        }
    }

    pub fn add_entry(
        &mut self,
        addr: Ipv4Addr,
        mask: Ipv4Addr,
        gateway: Ipv4Gateway,
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

    pub fn loopuk_gateway(&self, dest: Ipv4Addr) -> Option<(&Ipv4Gateway, &IfId)> {
        let now = SimTime::now();

        let mut state = 0;
        let mut result = None;
        let mut result_prefixlen = 0;

        for i in 0..self.entries.len() {
            if ipv4_matches_subnet(dest, self.entries[i].addr, self.entries[i].mask)
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

fn prefixlen(ip: Ipv4Addr) -> u32 {
    u32::from_be_bytes(ip.octets()).leading_ones()
}
