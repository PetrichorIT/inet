use crate::interface::InterfaceName;
use std::{fmt::Display, io, net::Ipv4Addr};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RoutingTableId(usize);
impl RoutingTableId {
    pub const DEFAULT: RoutingTableId = RoutingTableId(0);
}

#[derive(Debug)]
pub(crate) struct FwdV4 {
    tables: Vec<FwdTableV4>,
}

impl FwdV4 {
    pub(crate) fn new() -> Self {
        Self {
            tables: vec![FwdTableV4::new()],
        }
    }

    pub fn len(&self) -> usize {
        self.tables.len()
    }

    pub(crate) fn set_default_gw(&mut self, gateway: Ipv4Gateway, iface: InterfaceName) {
        self.tables
            .last_mut()
            .expect("no tables, not allowed")
            .set_default_gw(gateway, iface)
    }

    pub(crate) fn lookup(&self, addr: Ipv4Addr) -> Option<(&Ipv4Gateway, &InterfaceName)> {
        for table in self.tables.iter().rev() {
            if let Some(ret) = table.lookup(addr) {
                return Some(ret);
            }
        }
        None
    }

    pub(crate) fn add_table(&mut self) -> io::Result<RoutingTableId> {
        self.tables.push(FwdTableV4::new());
        Ok(RoutingTableId(self.len() - 1))
    }

    pub(crate) fn add_entry(&mut self, entry: FwdEntryV4, table_id: RoutingTableId) {
        self.tables[table_id.0].add_entry(entry)
    }

    pub(crate) fn entries(&self) -> Vec<FwdEntryV4> {
        let mut ret = Vec::with_capacity(32);
        for table in self.tables.iter().rev() {
            ret.extend(table.entries.iter().cloned());
        }
        ret
    }
}

#[derive(Debug)]
pub(crate) struct FwdTableV4 {
    // A list of all fwd entrys with the smallest prefixes first
    pub(super) entries: Vec<FwdEntryV4>,
}

/// A forwarding entry. Will not expire since FWD should be managed manually by routing deamons
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FwdEntryV4 {
    /// The subnet this entry points to.
    pub dest: Ipv4Addr,
    /// The netmask of the targeted subnet.
    pub mask: Ipv4Addr,
    /// The next gateway on the route to the target.
    pub gateway: Ipv4Gateway,
    /// The interface to be used to forward to the gateway.
    pub iface: InterfaceName,
}

/// A type that describes differnt types of packet forwarding in inet.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Ipv4Gateway {
    /// This option indicates that packets should be forwarded to a bound LAN.
    Local,
    /// This option is used for the representation of broadcasts.
    Broadcast,
    /// This option instructs inet to forward packets to the next gateway.
    Gateway(Ipv4Addr),
}

impl FwdTableV4 {
    pub(crate) fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    pub(crate) fn set_default_gw(&mut self, gateway: Ipv4Gateway, iface: InterfaceName) {
        if let Some(f) = self.entries.first_mut() {
            if f.is_default_gw() {
                f.gateway = gateway;
                f.iface = iface;
            } else {
                self.entries
                    .insert(0, FwdEntryV4::default_gw(gateway, iface))
            }
        } else {
            self.entries.push(FwdEntryV4::default_gw(gateway, iface));
        }
    }

    pub(crate) fn add_entry(&mut self, entry: FwdEntryV4) {
        if let Some(in_place) = self.entries.iter_mut().find(|e| e.matches(&entry)) {
            *in_place = entry;
        } else {
            match self.entries.binary_search_by(|e| e.mask.cmp(&entry.mask)) {
                Ok(i) | Err(i) => self.entries.insert(i, entry),
            }
        }
    }

    pub(crate) fn lookup(&self, addr: Ipv4Addr) -> Option<(&Ipv4Gateway, &InterfaceName)> {
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

impl FwdEntryV4 {
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

impl Display for FwdEntryV4 {
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
        let mut fwd = FwdTableV4::new();
        fwd.set_default_gw(Ipv4Gateway::Local, InterfaceName::new("gw"));
        fwd.add_entry(FwdEntryV4 {
            dest: Ipv4Addr::new(1, 2, 3, 0),
            mask: Ipv4Addr::new(255, 255, 255, 0),
            gateway: Ipv4Gateway::Local,
            iface: InterfaceName::new("sub24"),
        });
        fwd.add_entry(FwdEntryV4 {
            dest: Ipv4Addr::new(1, 2, 0, 0),
            mask: Ipv4Addr::new(255, 255, 0, 0),
            gateway: Ipv4Gateway::Local,
            iface: InterfaceName::new("sub16"),
        });

        assert_eq!(
            fwd.entries,
            vec![
                FwdEntryV4::default_gw(Ipv4Gateway::Local, InterfaceName::new("gw")),
                FwdEntryV4 {
                    dest: Ipv4Addr::new(1, 2, 0, 0),
                    mask: Ipv4Addr::new(255, 255, 0, 0),
                    gateway: Ipv4Gateway::Local,
                    iface: InterfaceName::new("sub16"),
                },
                FwdEntryV4 {
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
        let mut fwd = FwdTableV4::new();
        fwd.set_default_gw(Ipv4Gateway::Local, InterfaceName::new("gw"));
        fwd.add_entry(FwdEntryV4 {
            dest: Ipv4Addr::new(1, 2, 3, 0),
            mask: Ipv4Addr::new(255, 255, 255, 0),
            gateway: Ipv4Gateway::Local,
            iface: InterfaceName::new("sub24"),
        });
        fwd.add_entry(FwdEntryV4 {
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
