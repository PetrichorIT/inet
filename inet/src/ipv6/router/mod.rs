use des::time::SimTime;
use inet_types::ip::Ipv6Prefix;
use std::{net::Ipv6Addr, time::Duration};

use crate::interface::IfId;

mod api;
pub use api::*;

pub struct RouterState {
    pub last_adv_sent: SimTime,
}

impl RouterState {
    pub fn new() -> Self {
        Self {
            last_adv_sent: SimTime::MAX,
        }
    }
}

/// A prefix matching routing table
pub struct Router {
    pub entries: Vec<Entry>,
}

pub struct Entry {
    pub prefix: Ipv6Prefix,
    pub next_hop: Ipv6Addr,
    pub ifid: IfId,
    pub expires: SimTime,
}

impl Router {
    pub fn new() -> Self {
        Router {
            entries: Vec::new(),
        }
    }

    pub fn lookup(&self, dst: Ipv6Addr) -> Option<(Ipv6Addr, IfId)> {
        if dst.is_multicast() {
            return Some((dst, IfId::NULL));
        }
        self.entries
            .iter()
            .find(|e| e.prefix.contains(dst))
            .map(|e| (e.next_hop, e.ifid))
            .map(|e| {
                tracing::trace!("choose route towards {dst} -> {} over {}", e.0, e.1);
                e
            })
    }

    pub fn add(&mut self, prefix: Ipv6Prefix, next_hop: Ipv6Addr, ifid: IfId) {
        let entry = Entry {
            prefix,
            next_hop,
            ifid,
            expires: SimTime::now() + Duration::from_secs(60),
        };
        match self
            .entries
            .binary_search_by(|l| l.prefix.len().cmp(&prefix.len()))
        {
            Ok(i) | Err(i) => self.entries.insert(i, entry),
        }
    }
}
