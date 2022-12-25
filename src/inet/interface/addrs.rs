use std::{
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

/// A interface addr.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum InterfaceAddr {
    /// A hardware ethernet address.
    Ether {
        /// The MAC addr.
        addr: [u8; 6],
    },
    /// An Ipv4 declaration
    Inet {
        /// The net addr,
        addr: Ipv4Addr,
        /// The mask to create the subnet.
        netmask: Ipv4Addr,
    },
    /// The Ipv6 declaration
    Inet6 {
        /// The net addr.
        addr: Ipv6Addr,
        /// The mask to create the subnet
        prefixlen: usize,
        /// Scoping.
        scope_id: Option<usize>,
    },
}

impl InterfaceAddr {
    /// Returns the addrs for a loopback interface.
    pub const fn loopback() -> [Self; 3] {
        [
            InterfaceAddr::Inet {
                addr: Ipv4Addr::LOCALHOST,
                netmask: Ipv4Addr::new(255, 0, 0, 0),
            },
            InterfaceAddr::Inet6 {
                addr: Ipv6Addr::LOCALHOST,
                prefixlen: 128,
                scope_id: None,
            },
            InterfaceAddr::Inet6 {
                addr: Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1),
                prefixlen: 64,
                scope_id: Some(0x1),
            },
        ]
    }

    /// Returns the addrs for a loopback interface.
    pub const fn en0(ether: [u8; 6], v4: Ipv4Addr) -> [Self; 2] {
        [
            InterfaceAddr::Ether { addr: ether },
            InterfaceAddr::Inet {
                addr: v4,
                netmask: Ipv4Addr::new(255, 255, 255, 0),
            },
        ]
    }

    /// Indicates whether the given ip is valid on the interface address.
    pub fn matches_ip(&self, ip: IpAddr) -> bool {
        match self {
            Self::Inet { addr, netmask } if ip.is_ipv4() => {
                let ip = if let IpAddr::V4(v) = ip {
                    v
                } else {
                    unreachable!()
                };

                if ip.is_broadcast() {
                    return true;
                }

                let ip_u32 = u32::from_be_bytes(ip.octets());
                let addr_u32 = u32::from_be_bytes(addr.octets());
                let mask_u32 = u32::from_be_bytes(netmask.octets());
                mask_u32 & ip_u32 == mask_u32 & addr_u32
            }
            Self::Inet6 { .. } if ip.is_ipv6() => {
                todo!()
            }
            _ => false,
        }
    }

    /// Returns an available Ip.
    pub fn next_ip(&self) -> Option<IpAddr> {
        match self {
            Self::Ether { .. } => None,
            Self::Inet { addr, .. } => Some(IpAddr::V4(*addr)),
            Self::Inet6 { addr, .. } => Some(IpAddr::V6(*addr)),
        }
    }
}

impl fmt::Display for InterfaceAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            Self::Ether { addr } => write!(
                f,
                "ether {}:{}:{}:{}:{}:{}",
                addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]
            ),
            Self::Inet { addr, netmask } => write!(f, "inet {} netmask {}", addr, netmask),
            Self::Inet6 {
                addr,
                prefixlen,
                scope_id,
            } => write!(
                f,
                "inet6 {} prefixlen {}{}",
                addr,
                prefixlen,
                if let Some(scope_id) = scope_id {
                    format!(" scopeid: 0x{:x}", scope_id)
                } else {
                    String::new()
                }
            ),
        }
    }
}
