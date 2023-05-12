use crate::interface::InterfaceName;
use std::{fmt::Display, net::Ipv4Addr};

pub struct ForwardingTableV4 {
    // A list of all fwd entrys with the smallest prefixes first
    pub(super) entries: Vec<ForwardingEntryV4>,
}

/// A forwarding entry. Will not expire since FWD should be managed manually by routing deamons
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ForwardingEntryV4 {
    pub dest: Ipv4Addr,
    pub mask: Ipv4Addr,
    pub gateway: Ipv4Gateway,
    pub iface: InterfaceName,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Ipv4Gateway {
    Local,
    Broadcast,
    Gateway(Ipv4Addr),
}

impl ForwardingTableV4 {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    pub fn set_default_gw(&mut self, gateway: Ipv4Gateway, iface: InterfaceName) {
        if let Some(f) = self.entries.first_mut() {
            if f.is_default_gw() {
                f.gateway = gateway;
                f.iface = iface;
            } else {
                self.entries
                    .insert(0, ForwardingEntryV4::default_gw(gateway, iface))
            }
        } else {
            self.entries
                .push(ForwardingEntryV4::default_gw(gateway, iface));
        }
    }

    pub fn add_entry(&mut self, entry: ForwardingEntryV4) {
        if let Some(in_place) = self.entries.iter_mut().find(|e| e.matches(&entry)) {
            *in_place = entry;
        } else {
            match self.entries.binary_search_by(|e| e.mask.cmp(&entry.mask)) {
                Ok(i) | Err(i) => self.entries.insert(i, entry),
            }
        }
    }

    pub fn lookup(&self, addr: Ipv4Addr) -> Option<(&Ipv4Gateway, &InterfaceName)> {
        let addr = u32::from(addr);
        for entry in self.entries.iter().rev() {
            let mask = u32::from(entry.mask);
            if addr & mask == u32::from(entry.dest) & mask {
                return Some((&entry.gateway, &entry.iface));
            }
        }
        None
    }
}

impl ForwardingEntryV4 {
    pub(crate) fn default_gw(gateway: Ipv4Gateway, iface: InterfaceName) -> Self {
        Self {
            dest: Ipv4Addr::UNSPECIFIED,
            mask: Ipv4Addr::UNSPECIFIED,
            gateway,
            iface,
        }
    }

    pub(crate) fn broadcast(iface: InterfaceName) -> Self {
        Self {
            dest: Ipv4Addr::BROADCAST,
            mask: Ipv4Addr::BROADCAST,
            gateway: Ipv4Gateway::Broadcast,
            iface,
        }
    }

    fn matches(&self, other: &Self) -> bool {
        self.dest == other.dest && self.mask == other.mask
    }

    fn is_default_gw(&self) -> bool {
        self.dest == Ipv4Addr::UNSPECIFIED && self.mask == Ipv4Addr::UNSPECIFIED
    }
}

impl Display for ForwardingEntryV4 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} ({}) via {:?} on {}",
            self.dest, self.mask, self.gateway, self.iface
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn netmask_ordering() {
        let mut fwd = ForwardingTableV4::new();
        fwd.set_default_gw(Ipv4Gateway::Local, InterfaceName::new("gw"));
        fwd.add_entry(ForwardingEntryV4 {
            dest: Ipv4Addr::new(1, 2, 3, 0),
            mask: Ipv4Addr::new(255, 255, 255, 0),
            gateway: Ipv4Gateway::Local,
            iface: InterfaceName::new("sub24"),
        });
        fwd.add_entry(ForwardingEntryV4 {
            dest: Ipv4Addr::new(1, 2, 0, 0),
            mask: Ipv4Addr::new(255, 255, 0, 0),
            gateway: Ipv4Gateway::Local,
            iface: InterfaceName::new("sub16"),
        });

        assert_eq!(
            fwd.entries,
            vec![
                ForwardingEntryV4::default_gw(Ipv4Gateway::Local, InterfaceName::new("gw")),
                ForwardingEntryV4 {
                    dest: Ipv4Addr::new(1, 2, 0, 0),
                    mask: Ipv4Addr::new(255, 255, 0, 0),
                    gateway: Ipv4Gateway::Local,
                    iface: InterfaceName::new("sub16"),
                },
                ForwardingEntryV4 {
                    dest: Ipv4Addr::new(1, 2, 3, 0),
                    mask: Ipv4Addr::new(255, 255, 255, 0),
                    gateway: Ipv4Gateway::Local,
                    iface: InterfaceName::new("sub24"),
                }
            ]
        )
    }

    #[test]
    fn lookup() {
        let mut fwd = ForwardingTableV4::new();
        fwd.set_default_gw(Ipv4Gateway::Local, InterfaceName::new("gw"));
        fwd.add_entry(ForwardingEntryV4 {
            dest: Ipv4Addr::new(1, 2, 3, 0),
            mask: Ipv4Addr::new(255, 255, 255, 0),
            gateway: Ipv4Gateway::Local,
            iface: InterfaceName::new("sub24"),
        });
        fwd.add_entry(ForwardingEntryV4 {
            dest: Ipv4Addr::new(1, 2, 0, 0),
            mask: Ipv4Addr::new(255, 255, 0, 0),
            gateway: Ipv4Gateway::Local,
            iface: InterfaceName::new("sub16"),
        });

        assert_eq!(
            fwd.lookup(Ipv4Addr::new(1, 2, 3, 4)).map(|(_, g)| g),
            Some(&InterfaceName::new("sub24"))
        );

        assert_eq!(
            fwd.lookup(Ipv4Addr::new(1, 2, 10, 4)).map(|(_, g)| g),
            Some(&InterfaceName::new("sub16"))
        );

        assert_eq!(
            fwd.lookup(Ipv4Addr::new(2, 2, 3, 4)).map(|(_, g)| g),
            Some(&InterfaceName::new("gw"))
        );
    }
}
