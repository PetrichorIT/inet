use des::time::SimTime;
use std::{collections::HashMap, net::Ipv4Addr, time::Duration};

use crate::{interface2::IfId, interface2::MacAddress, ip::Ipv4Packet};

pub struct ARPTable {
    map: HashMap<Ipv4Addr, ARPEntry>,
    config: ARPConfig,
    buffer: HashMap<Ipv4Addr, Vec<Ipv4Packet>>,
}

pub struct ARPConfig {
    pub validity: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ARPEntry {
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

    pub fn lookup(&self, ip: &Ipv4Addr) -> Option<&ARPEntry> {
        let Some(value) = self.map.get(ip) else {
            return None
        };
        if value.expires <= SimTime::now() {
            None
        } else {
            Some(value)
        }
    }

    pub fn add(&mut self, mut entry: ARPEntry) -> Option<Vec<Ipv4Packet>> {
        let ip = entry.ip;
        entry.expires = SimTime::now() + self.config.validity;
        let _ = self.map.insert(ip, entry);
        // if old.is_none() {
        //     log::trace!(target: "inet/arp", "new entry {ip}")
        // }
        self.buffer.remove(&ip)
    }

    pub fn wait_for_arp(&mut self, ip: Ipv4Packet) {
        let dest = ip.dest;
        self.buffer.entry(dest).or_insert(Vec::new()).push(ip)
    }
}
