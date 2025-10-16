use std::{fmt::Display, io::Result, net::Ipv4Addr};

use des::time::SimTime;
use types::iface::MacAddress;

use super::ArpConfig;
use crate::{IOContext, IOHandle, interface::InterfaceName, ioctx, socket::SocketIfaceBinding};

/// An entry in the address resoloution table
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ArpEntry {
    /// A human-readable name for the resolved node
    pub hostname: Option<String>,
    /// The IP address mapped to the MAC address
    pub ip: Ipv4Addr,
    /// The MAC address of the related IP address
    pub mac: MacAddress,
    /// An identifier for the related interface
    pub iface: InterfaceName,
    /// A flag indicating whether the ARP entry will expire.
    pub permanent: bool,
}

impl Display for ArpEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} ({}) at {} on {} ifscope {}[ethernet]",
            self.hostname.as_deref().unwrap_or("?"),
            self.ip,
            self.mac,
            self.iface,
            if self.permanent { "permanent " } else { "" }
        )
    }
}

/// Display the IP network neighbor table
///
/// This function is roughly equivalent to the shell command
/// `arp -a`. On success this function returns a list of all
/// valid entries in the neighbor table, with additional
/// metadata attached.
///
/// # Examples
///
/// ```no_run
/// use inet::ipv4::arp::arpa;
///
/// /* ... */
/// # fn main() -> std::io::Result<()> {
/// let results = arpa()?;
/// for line in results {
///     println!("{line}")
/// }
/// # Ok(())
/// # }
/// /* ... */
///
/// ```
pub fn arpa() -> Result<Vec<ArpEntry>> {
    ioctx().arpa()
}

/// Adds a permantent entry to the IP network neighbor table
pub fn set_arp_entry(ip: Ipv4Addr, mac: MacAddress, if_name: InterfaceName) -> Result<()> {
    ioctx().set_arp_entry(ip, mac, if_name)
}

/// Sets the configuration of the ARP table
///
/// Note that this change will only affect newer
/// entries and not propagate to older ones.
pub fn set_arp_config(cfg: ArpConfig) -> Result<()> {
    ioctx().set_arp_config(cfg)
}

impl IOHandle {
    pub fn arpa(&self) -> Result<Vec<ArpEntry>> {
        self.do_failable(|ctx| Ok(ctx.arpa()))
    }

    pub fn set_arp_entry(
        &self,
        ip: Ipv4Addr,
        mac: MacAddress,
        if_name: InterfaceName,
    ) -> Result<()> {
        self.do_failable(|ctx| ctx.set_arp_entry(ip, mac, if_name))
    }

    pub fn set_arp_config(&self, cfg: ArpConfig) -> Result<()> {
        self.do_failable(|ctx| ctx.set_arp_config(cfg))
    }
}

impl IOContext {
    fn arpa(&mut self) -> Vec<ArpEntry> {
        let mut results = Vec::with_capacity(self.ipv4.arp.len());
        let now = SimTime::now();
        for entry in self.ipv4.arp.entries() {
            if entry.expires < now {
                continue;
            }

            let permanent = entry.expires == SimTime::MAX;
            let iface = if let Some(iface) = self.ifaces.get_mut_spec(&entry.iface) {
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

    fn set_arp_entry(
        &mut self,
        ip: Ipv4Addr,
        mac: MacAddress,
        if_name: InterfaceName,
    ) -> Result<()> {
        let sendable = self.ipv4.arp.update(super::ArpEntryInternal {
            negated: false,
            hostname: None,
            ip,
            mac,
            iface: Some(if_name.id()),
            expires: SimTime::MAX,
        });
        if let Some((trg, sendable)) = sendable {
            for pkt in sendable {
                self.ipv4_send_lan_local(SocketIfaceBinding::Bound(if_name.id()), trg, pkt)
                    .unwrap();
            }
        }
        Ok(())
    }

    fn set_arp_config(&mut self, cfg: ArpConfig) -> Result<()> {
        self.ipv4.arp.config = cfg;
        Ok(())
    }
}
