use std::{io::Result, net::IpAddr};

use types::iface::MacAddress;

use crate::{interface::InterfaceAddr, IOContext};

/// Returns the first MAC address of the current node.
///
/// This address can be used as a UID, as long as the interface configuration does
/// not change. May return `None` if no interface is bound.
///
/// # Errors
///
/// This function fails, if called from outside of a node context.
pub fn get_mac_address() -> Result<Option<MacAddress>> {
    IOContext::failable_api(|ctx| ctx.get_mac_address())
}

/// Returns the first IP address of the current node.
///
/// May return `None` if no interface is bound.
///
/// # Errors
///
/// This function fails, if called from outside of a node context.
pub fn get_ip() -> Option<IpAddr> {
    IOContext::with_current(|ctx| ctx.get_ip())
}

pub fn getaddrinfo() -> Result<AddrInfo> {
    IOContext::failable_api(|ctx| Ok(ctx.getaddrinfo()))
}

pub type AddrInfo = Vec<IpAddr>;

impl IOContext {
    /// Returns ethernet mac address for a given IOContext
    pub(crate) fn get_mac_address(&self) -> Result<Option<MacAddress>> {
        for (_, interface) in &self.ifaces {
            if interface.device.addr == MacAddress::NULL {
                continue;
            }
            return Ok(Some(interface.device.addr));
        }

        Ok(None)
    }

    pub(crate) fn get_ip(&self) -> Option<IpAddr> {
        for (_, interface) in &self.ifaces {
            for addr in interface.addrs.iter() {
                if let InterfaceAddr::Inet(addr) = addr {
                    return Some(IpAddr::V4(addr.addr));
                }
                if let InterfaceAddr::Inet6(addr) = addr {
                    return Some(IpAddr::V6(addr.addr));
                }
            }
        }
        None
    }

    pub(crate) fn getaddrinfo(&self) -> AddrInfo {
        let mut info = AddrInfo::new();
        for (_, iface) in &self.ifaces {
            for addr in iface.addrs.iter() {
                match addr {
                    InterfaceAddr::Inet(binding) => info.push(IpAddr::V4(binding.addr)),
                    InterfaceAddr::Inet6(binding) => info.push(IpAddr::V6(binding.addr)),
                }
            }
        }
        info
    }
}
