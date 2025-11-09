use std::{io::Result, net::IpAddr};

use types::iface::MacAddress;

use crate::{IOContext, IOHandle, ioctx};

/// Returns the first MAC address of the current node.
///
/// This address can be used as a UID, as long as the interface configuration does
/// not change. May return `None` if no interface is bound.
///
/// # Errors
///
/// This function fails, if called from outside of a node context.
pub fn get_mac_address() -> Result<Option<MacAddress>> {
    ioctx().do_failable(|ctx| ctx.get_mac_address())
}

/// Returns the first IP address of the current node.
///
/// May return `None` if no interface is bound.
///
/// # Errors
///
/// This function fails, if called from outside of a node context.
pub fn get_ip() -> Option<IpAddr> {
    ioctx().do_io(|ctx| ctx.get_ip())
}

pub fn getaddrinfo() -> Result<AddrInfo> {
    ioctx().getaddrinfo()
}

pub type AddrInfo = Vec<IpAddr>;

impl IOHandle {
    pub fn getaddrinfo(&self) -> Result<AddrInfo> {
        self.do_failable(|ctx| Ok(ctx.getaddrinfo()))
    }
}

impl IOContext {
    /// Returns ethernet mac address for a given IOContext
    pub(crate) fn get_mac_address(&self) -> Result<Option<MacAddress>> {
        for interface in self.ifaces.values() {
            if interface.device.addr == MacAddress::NULL {
                continue;
            }
            return Ok(Some(interface.device.addr));
        }

        Ok(None)
    }

    pub(crate) fn get_ip(&self) -> Option<IpAddr> {
        for interface in self.ifaces.values() {
            if let Some(binding) = interface.bindings.v4.unicast.first() {
                return Some(IpAddr::V4(binding.addr));
            }
            if let Some(binding) = interface.bindings.v6.unicast.first() {
                return Some(IpAddr::V6(binding.addr));
            }
        }
        None
    }

    pub(crate) fn getaddrinfo(&self) -> AddrInfo {
        let mut info = AddrInfo::new();
        for iface in self.ifaces.values() {
            for binding in &iface.bindings.v4.unicast {
                info.push(binding.addr.into())
            }
            for binding in &iface.bindings.v6.unicast {
                info.push(binding.addr.into())
            }
        }
        info
    }
}

#[cfg(test)]
mod tests {
    use des::runtime::RuntimeError;
    use serial_test::serial;
    use types::iface::MacAddress;

    use crate::{
        interface::{InterfaceDef, NetworkDevice},
        ioctx,
        utils::SimpleSim,
    };

    use super::get_mac_address;

    #[test]
    #[serial]
    fn get_mac_addr() -> Result<(), RuntimeError> {
        let mut sim = SimpleSim::default();
        sim.raw("alice", |_| async move {
            assert_eq!(None, get_mac_address()?);

            let addr = MacAddress::generate();
            ioctx().add_interface(InterfaceDef::ethv6_autocfg(
                NetworkDevice::eth().with_addr(addr),
            ))?;

            assert_eq!(Some(addr), get_mac_address()?);

            Ok(())
        });

        sim.run()
    }
}
