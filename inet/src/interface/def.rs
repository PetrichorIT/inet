use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::Duration,
};

use des::time::SimTime;
use types::ip::Ipv6AddrExt;

use super::{
    InterfaceAddrV4, InterfaceAddrV6, InterfaceController, InterfaceFlags, InterfaceName,
    NetworkDevice,
};

/// An interface definition.
#[derive(Debug)]
pub struct InterfaceDef {
    /// The name of the interface.
    pub name: InterfaceName,
    /// The flags associated with the interface.
    pub flags: InterfaceFlags,
    /// The network device associated with the interface.
    pub device: NetworkDevice,
    /// The addresses associated with the interface.
    pub addrs: InterfaceAddrsDef,
}

pub const DEFAULT_MTU: usize = 1500;
pub const DEFAULT_V4_MASK: Ipv4Addr = Ipv4Addr::new(255, 255, 255, 0);
pub const DEFAULT_V6_MASK: Ipv6Addr = Ipv6Addr::new(0xffff, 0xffff, 0xffff, 0xffff, 0, 0, 0, 0);

/// The addresses associated with an interface.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct InterfaceAddrsDef {
    /// IPv4 unicast addresses + netmasks that should be bound to the interface.
    pub ipv4: Vec<(Ipv4Addr, Ipv4Addr)>,
    /// IPv6 unicast addresses + netmasks that should be bound to the interface.
    pub ipv6: Vec<(Ipv6Addr, Ipv6Addr)>,
}

impl InterfaceDef {
    pub(crate) fn into_legacy(self) -> InterfaceController {
        let mut iface = InterfaceController::empty(&self.name, self.device);
        iface.flags = self.flags;

        for (addr, mask) in self.addrs.ipv4 {
            iface.bindings.v4.add(InterfaceAddrV4::new(addr, mask));
        }
        for (addr, mask) in self.addrs.ipv6 {
            iface.flags.v6 = true;
            iface.bindings.v6.add(InterfaceAddrV6 {
                addr,
                mask,
                deadline: SimTime::MAX,
                validity: Duration::MAX,
                flags: super::InterfaceAddrV6Flags {
                    temporary: false,
                    home_addr: false,
                    care_of_addr: false,
                },
            });
        }
        iface
    }

    pub fn ethv6_autocfg(device: NetworkDevice) -> Self {
        Self::new("en0", device).ipv6_link_local()
    }

    pub fn loopback() -> Self {
        Self {
            name: InterfaceName::new("lo0"),
            flags: InterfaceFlags::loopback(),
            device: NetworkDevice::loopback(),
            addrs: InterfaceAddrsDef::loopback(),
        }
    }

    pub fn new(name: &str, device: NetworkDevice) -> Self {
        Self {
            name: InterfaceName::new(name),
            flags: InterfaceFlags::en0(false),
            device,
            addrs: InterfaceAddrsDef::default(),
        }
    }

    pub fn v6(mut self) -> Self {
        self.flags.v6 = true;
        self
    }

    pub fn ip(self, addr: IpAddr) -> Self {
        match addr {
            IpAddr::V4(addr) => self.ipv4(addr, DEFAULT_V4_MASK),
            IpAddr::V6(addr) => self.ipv6(addr, DEFAULT_V6_MASK),
        }
    }

    #[must_use]
    pub fn ipv4(mut self, addr: Ipv4Addr, mask: Ipv4Addr) -> Self {
        self.addrs.ipv4.push((addr, mask));
        self
    }

    #[must_use]
    pub fn ipv6(mut self, addr: Ipv6Addr, mask: Ipv6Addr) -> Self {
        self.addrs.ipv6.push((addr, mask));
        self.flags.v6 = true;
        self
    }

    #[must_use]
    pub fn ipv6_link_local(mut self) -> Self {
        self.addrs.ipv6.push((
            self.device.addr.embed_into(Ipv6Addr::LINK_LOCAL),
            DEFAULT_V6_MASK,
        ));
        self.flags.v6 = true;
        self
    }
}

impl InterfaceAddrsDef {
    pub fn loopback() -> Self {
        Self {
            ipv4: vec![(Ipv4Addr::LOCALHOST, DEFAULT_V4_MASK)],
            ipv6: vec![(Ipv6Addr::LOCALHOST, Ipv6Addr::from_bits(u128::MAX))],
        }
    }
}
