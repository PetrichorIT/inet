use des::time::SimTime;
use std::{
    collections::HashMap,
    hash::Hash,
    net::{IpAddr, Ipv4Addr},
    time::Duration,
};

use crate::{
    interface::IfId,
    interface::{Interface, MacAddress},
    ip::Ipv4Packet,
};

pub struct ARPTable {
    pub(super) map: HashMap<Ipv4Addr, ARPEntryInternal>,
    pub(super) config: ARPConfig,
    pub(super) buffer: HashMap<Ipv4Addr, Vec<Ipv4Packet>>,
}

pub struct ARPConfig {
    pub validity: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ARPEntryInternal {
    pub hostname: Option<String>,
    pub ip: Ipv4Addr,
    pub mac: MacAddress,
    pub iface: IfId,
    pub expires: SimTime,
}

impl ARPTable {
    pub fn new(config: ARPConfig) -> Self {
        Self {
            map: HashMap::new(),
            config,
            buffer: HashMap::new(),
        }
    }

    pub fn lookup_for_iface(&self, ip: &Ipv4Addr, iface: &Interface) -> Option<(MacAddress, IfId)> {
        self.lookup(ip).map(|e| (e.mac, e.iface)).or_else(|| {
            let looback = iface.flags.loopback && ip.is_loopback();
            let self_addr = iface
                .addrs
                .iter()
                .any(|addr| addr.matches_ip(IpAddr::V4(*ip)));
            if looback || self_addr {
                Some((iface.device.addr, iface.name.id))
            } else {
                None
            }
        })
    }

    pub fn lookup(&self, ip: &Ipv4Addr) -> Option<&ARPEntryInternal> {
        let Some(value) = self.map.get(ip) else {
            return None
        };
        if value.expires <= SimTime::now() {
            None
        } else {
            Some(value)
        }
    }

    #[must_use]
    pub fn add(&mut self, mut entry: ARPEntryInternal) -> Option<(Ipv4Addr, Vec<Ipv4Packet>)> {
        let ip = entry.ip;
        if entry.expires == SimTime::ZERO {
            entry.expires = SimTime::now() + self.config.validity;
        }

        let _ = self.map.insert(ip, entry);
        self.buffer.remove(&ip).map(|msgs| (ip, msgs))
    }

    pub fn wait_for_arp(&mut self, ip: Ipv4Packet, dest: Ipv4Addr) {
        self.buffer.entry(dest).or_insert(Vec::new()).push(ip)
    }

    pub fn active_lookup(&mut self, ip: &Ipv4Addr) -> bool {
        self.buffer
            .get(ip)
            .map(|buf| !buf.is_empty())
            .unwrap_or(false)
    }
}
