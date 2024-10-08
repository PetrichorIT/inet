use std::{fmt::Display, io::Result, net::IpAddr};

use des::time::SimTime;
use types::iface::MacAddress;

use super::ArpConfig;
use crate::{interface::InterfaceName, socket::SocketIfaceBinding, IOContext};

/// An entry in the address resoloution table
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ArpEntry {
    /// A human-readable name for the resolved node
    pub hostname: Option<String>,
    /// The IP address mapped to the MAC address
    pub ip: IpAddr,
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
            self.hostname.as_ref().map(|s| s.as_str()).unwrap_or("?"),
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
/// use inet::arp::arpa;
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
    IOContext::failable_api(|ctx| Ok(ctx.arpa()))
}

/// Adds a permantent entry to the IP network neighbor table
pub fn set_arp_entry(ip: IpAddr, mac: MacAddress, if_name: InterfaceName) -> Result<()> {
    IOContext::failable_api(|ctx| ctx.set_arp_entry(ip, mac, if_name))
}

/// Sets the configuration of the ARP table
///
/// Note that this change will only affect newer
/// entries and not propagate to older ones.
pub fn set_arp_config(cfg: ArpConfig) -> Result<()> {
    IOContext::failable_api(|ctx| ctx.set_arp_config(cfg))
}

impl IOContext {
    fn arpa(&mut self) -> Vec<ArpEntry> {
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

    fn set_arp_entry(&mut self, ip: IpAddr, mac: MacAddress, if_name: InterfaceName) -> Result<()> {
        let sendable = self.arp.update(super::ArpEntryInternal {
            negated: false,
            hostname: None,
            ip,
            mac,
            iface: if_name.id,
            expires: SimTime::MAX,
        });
        if let Some((trg, sendable)) = sendable {
            for pkt in sendable {
                self.send_lan_local_ip_packet(
                    SocketIfaceBinding::Bound(if_name.id),
                    trg,
                    pkt,
                    true,
                )
                .unwrap();
            }
        }
        Ok(())
    }

    fn set_arp_config(&mut self, cfg: ArpConfig) -> Result<()> {
        self.arp.config = cfg;
        Ok(())
    }
}
