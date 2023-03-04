use super::{Interface, InterfaceAddr};
use crate::IOContext;
use std::{io::Result, net::IpAddr};

pub fn add_interface(iface: Interface) {
    IOContext::with_current(|ctx| ctx.add_interface(iface))
}

pub fn get_interfaces() -> Vec<Interface> {
    IOContext::with_current(|ctx| ctx.get_interfaces())
}

pub fn get_mac_address() -> Result<Option<[u8; 6]>> {
    IOContext::with_current(|ctx| ctx.get_mac_address())
}

pub fn get_ip() -> Option<IpAddr> {
    IOContext::with_current(|ctx| ctx.get_ip())
}

impl IOContext {
    /// Returns ethernet mac address for a given IOContext
    pub fn get_mac_address(&self) -> Result<Option<[u8; 6]>> {
        for (_, interface) in &self.interfaces {
            for addr in &interface.addrs {
                if let InterfaceAddr::Ether { addr } = addr {
                    return Ok(Some(*addr));
                }
            }
        }

        Ok(None)
    }

    pub fn get_ip(&self) -> Option<IpAddr> {
        for (_, interface) in &self.interfaces {
            for addr in &interface.addrs {
                if let InterfaceAddr::Inet { addr, .. } = addr {
                    return Some(IpAddr::V4(*addr));
                }
                if let InterfaceAddr::Inet6 { addr, .. } = addr {
                    return Some(IpAddr::V6(*addr));
                }
            }
        }
        None
    }
}
