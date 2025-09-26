use des::time::SimTime;
use fxhash::{FxBuildHasher, FxHashMap};
use std::{hash::Hash, net::Ipv4Addr, time::Duration};

use crate::interface::IfId;
use types::{iface::MacAddress, ip::Ipv4Packet};

#[derive(Debug)]
pub(crate) struct ArpTable {
    pub(super) map: FxHashMap<Ipv4Addr, ArpEntryInternal>,
    pub(super) config: ArpConfig,
    pub(super) requests: FxHashMap<Ipv4Addr, ActiveRequest>,
    pub(super) active_wakeup: bool,
}

/// Configuration options for the Address Resolution Protocol (ARP)
#[derive(Debug)]
pub struct ArpConfig {
    /// The duration in which a entry is considered valid, without
    /// an explicit ARP handshake.
    pub validity: Duration,
    /// The timeout duration for reponses to an ARP
    /// request.
    pub timeout: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct ArpEntryInternal {
    pub negated: bool,
    pub hostname: Option<String>,
    pub ip: Ipv4Addr,
    pub mac: MacAddress,
    pub iface: IfId,
    pub expires: SimTime,
}

#[derive(Debug)]
pub(super) struct ActiveRequest {
    pub iface: IfId,
    pub deadline: SimTime,
    pub itr: usize,
    pub buffer: Vec<Ipv4Packet>,
}

impl Default for ArpConfig {
    fn default() -> Self {
        Self {
            validity: Duration::from_secs(200),
            timeout: Duration::from_secs(1),
        }
    }
}

impl ArpTable {
    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn entries(&self) -> impl Iterator<Item = &ArpEntryInternal> {
        self.map.values()
    }

    pub fn new() -> Self {
        Self::new_with(ArpConfig::default())
    }

    pub fn new_with(config: ArpConfig) -> Self {
        Self {
            map: FxHashMap::with_hasher(FxBuildHasher::default()),
            config,
            requests: FxHashMap::with_hasher(FxBuildHasher::default()),
            active_wakeup: false,
        }
    }

    pub fn lookup(&self, ip: &Ipv4Addr) -> Option<&ArpEntryInternal> {
        let value = self.map.get(ip)?;
        if value.expires <= SimTime::now() {
            None
        } else {
            Some(value)
        }
    }

    #[must_use]
    pub fn update(&mut self, mut entry: ArpEntryInternal) -> Option<(Ipv4Addr, Vec<Ipv4Packet>)> {
        self.tick();

        let ip = entry.ip;
        if entry.expires == SimTime::ZERO {
            entry.expires = SimTime::now() + self.config.validity;
        }

        let _ = self.map.insert(ip, entry);
        self.requests.remove(&ip).map(|msgs| (ip, msgs.buffer))
    }

    pub fn wait_for_arp(&mut self, ip: Ipv4Packet, dst: Ipv4Addr) {
        self.tick();

        self.requests
            .entry(dst)
            .or_insert(ActiveRequest {
                deadline: SimTime::now() + self.config.timeout,
                buffer: Vec::with_capacity(4),
                itr: 0,
                iface: IfId::NULL,
            })
            .buffer
            .push(ip);
    }

    pub fn active_lookup(&mut self, ip: &Ipv4Addr) -> bool {
        self.requests
            .get(ip)
            .map(|buf| !buf.buffer.is_empty())
            .unwrap_or(false)
    }

    pub fn tick(&mut self) {
        // let mut swap = FxHashMap::with_hasher(FxBuildHasher::default());
        // mem::swap(&mut swap, &mut self.requests);

        // for (addr, mut req) in swap {
        //     if req.deadline > SimTime::now() {
        //         self.requests.insert(addr, req);
        //     } else {
        //         req.itr += 1;
        //         self.retry.insert(addr, req);
        //     }
        // }

        // // self.requests.retain(|_, req| req.deadline > SimTime::now());
    }
}
