use des::time::SimTime;
use std::{collections::HashMap, hash::Hash, net::IpAddr, time::Duration};

use crate::{
    interface::IfId,
    interface::{Interface, MacAddress},
    ip::IpPacket,
};

pub struct ARPTable {
    map: HashMap<IpAddr, ARPEntryInternal>,
    config: ARPConfig,
    requests: HashMap<IpAddr, ActiveRequest>,
}

pub struct ARPConfig {
    pub validity: Duration,
    pub timeout: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ARPEntryInternal {
    pub hostname: Option<String>,
    pub ip: IpAddr,
    pub mac: MacAddress,
    pub iface: IfId,
    pub expires: SimTime,
}

struct ActiveRequest {
    deadline: SimTime,
    buffer: Vec<IpPacket>,
}

impl Default for ARPConfig {
    fn default() -> Self {
        Self {
            validity: Duration::from_secs(200),
            timeout: Duration::from_secs(2),
        }
    }
}

impl ARPTable {
    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn entries(&self) -> impl Iterator<Item = &ARPEntryInternal> {
        self.map.values()
    }

    pub fn new() -> Self {
        Self::new_with(ARPConfig::default())
    }

    pub fn new_with(config: ARPConfig) -> Self {
        Self {
            map: HashMap::new(),
            config,
            requests: HashMap::new(),
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
    pub fn update(&mut self, mut entry: ARPEntryInternal) -> Option<(IpAddr, Vec<IpPacket>)> {
        self.tick();

        let ip = entry.ip;
        if entry.expires == SimTime::ZERO {
            entry.expires = SimTime::now() + self.config.validity;
        }

        let _ = self.map.insert(ip, entry);
        self.requests.remove(&ip).map(|msgs| (ip, msgs.buffer))
    }

    pub fn wait_for_arp(&mut self, ip: IpPacket, dest: IpAddr) {
        self.tick();

        self.requests
            .entry(dest)
            .or_insert(ActiveRequest {
                deadline: SimTime::now() + self.config.timeout,
                buffer: Vec::with_capacity(4),
            })
            .buffer
            .push(ip);
    }

    pub fn active_lookup(&mut self, ip: &IpAddr) -> bool {
        self.requests
            .get(ip)
            .map(|buf| !buf.buffer.is_empty())
            .unwrap_or(false)
    }

    pub fn tick(&mut self) {
        self.requests.retain(|_, req| req.deadline > SimTime::now());
    }
}
