use std::{
    fmt::Display,
    io::{self, Error, ErrorKind},
    net::IpAddr,
};

use des::time::SimTime;

use crate::{
    interface::{InterfaceName, MacAddress},
    IOContext,
};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ArpEntry {
    pub hostname: Option<String>,
    pub ip: IpAddr,
    pub mac: MacAddress,
    pub iface: InterfaceName,
    pub permanent: bool,
}

impl Display for ArpEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} ({}) at {} on {} ifscope {}[ethernet]",
            self.hostname.as_ref().map(|s| s.as_str()).unwrap_or("?"),
            self.ip,
            self.mac,
            self.iface,
            if self.permanent { "permanent " } else { "" }
        )
    }
}

pub fn arpa() -> io::Result<Vec<ArpEntry>> {
    IOContext::try_with_current(|ctx| ctx.arpa())
        .ok_or(Error::new(ErrorKind::Other, "Missing IO plugin"))
}

impl IOContext {
    pub fn arpa(&mut self) -> Vec<ArpEntry> {
        let mut results = Vec::with_capacity(self.arp.len());
        let now = SimTime::now();
        for entry in self.arp.entries() {
            if entry.expires < now {
                continue;
            }

            let permanent = entry.expires == SimTime::MAX;
            let iface = if let Some(iface) = self.ifaces.get(&entry.iface) {
                iface.name.clone()
            } else {
                InterfaceName::new("?")
            };

            results.push(ArpEntry {
                hostname: entry.hostname.clone(),
                ip: entry.ip,
                mac: entry.mac,
                iface,
                permanent,
            })
        }

        results
    }
}
