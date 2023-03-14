use des::time::SimTime;
use std::{collections::HashMap, hash::Hash, net::IpAddr, time::Duration};

use crate::{
    interface::IfId,
    interface::{Interface, MacAddress},
    ip::IpPacket,
};

pub struct ARPTable {
    pub(super) map: HashMap<IpAddr, ARPEntryInternal>,
    pub(super) config: ARPConfig,
    pub(super) buffer: HashMap<IpAddr, Vec<IpPacket>>,
}

pub struct ARPConfig {
    pub validity: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ARPEntryInternal {
    pub hostname: Option<String>,
    pub ip: IpAddr,
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

    pub fn lookup_for_iface(&self, ip: &IpAddr, iface: &Interface) -> Option<(MacAddress, IfId)> {
        self.lookup(ip).map(|e| (e.mac, e.iface)).or_else(|| {
            let looback = iface.flags.loopback && ip.is_loopback();
            let self_addr = iface.addrs.iter().any(|addr| addr.matches_ip(*ip));
            if looback || self_addr {
                Some((iface.device.addr, iface.name.id))
            } else {
                None
            }
        })
    }

    pub fn lookup(&self, ip: &IpAddr) -> Option<&ARPEntryInternal> {
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
    pub fn add(&mut self, mut entry: ARPEntryInternal) -> Option<(IpAddr, Vec<IpPacket>)> {
        let ip = entry.ip;
        if entry.expires == SimTime::ZERO {
            entry.expires = SimTime::now() + self.config.validity;
        }

        let _ = self.map.insert(ip, entry);
        self.buffer.remove(&ip).map(|msgs| (ip, msgs))
    }

    pub fn wait_for_arp(&mut self, ip: IpPacket, dest: IpAddr) {
        self.buffer.entry(dest).or_insert(Vec::new()).push(ip)
    }

    pub fn active_lookup(&mut self, ip: &IpAddr) -> bool {
        self.buffer
            .get(ip)
            .map(|buf| !buf.is_empty())
            .unwrap_or(false)
    }
}
