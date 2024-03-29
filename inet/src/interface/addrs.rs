use std::{
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use inet_types::iface::MacAddress;

/// A interface addr.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum InterfaceAddr {
    /// A hardware ethernet address.
    Ether {
        /// The MAC addr.
        addr: MacAddress,
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
    pub fn loopback() -> [Self; 3] {
        [
            InterfaceAddr::Inet {
                addr: Ipv4Addr::LOCALHOST,
                netmask: Ipv4Addr::new(255, 255, 255, 0),
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
    pub fn en0(ether: MacAddress, v4: Ipv4Addr) -> [Self; 3] {
        let v6 = v4.to_ipv6_compatible();
        [
            InterfaceAddr::Ether { addr: ether },
            InterfaceAddr::Inet {
                addr: v4,
                netmask: Ipv4Addr::new(255, 255, 255, 0),
            },
            InterfaceAddr::Inet6 {
                addr: v6,
                prefixlen: 64,
                scope_id: Some(0x1),
            },
        ]
    }

    /// Returns whether an IP address matches a bound
    /// interface address.
    pub fn matches_ip(&self, ip: IpAddr) -> bool {
        match self {
            // # Default cases
            Self::Inet { addr, .. } if ip.is_ipv4() => {
                let ip = if let IpAddr::V4(v) = ip {
                    v
                } else {
                    unreachable!()
                };

                if ip.is_broadcast() {
                    return true;
                }

                *addr == ip
            }

            Self::Inet6 { addr, .. } if ip.is_ipv6() => {
                let ip = if let IpAddr::V6(v) = ip {
                    v
                } else {
                    unreachable!()
                };

                *addr == ip
            }
            _ => false,
        }
    }

    /// Indicates whether the given ip is valid on the interface address.
    pub fn matches_ip_subnet(&self, ip: IpAddr) -> bool {
        match self {
            // # Default cases
            Self::Inet { addr, netmask } if ip.is_ipv4() => {
                let ip = if let IpAddr::V4(v) = ip {
                    v
                } else {
                    unreachable!()
                };

                if ip.is_broadcast() {
                    return true;
                }

                // TODO: think about this is this good ?
                // if ip.is_loopback() {
                //     return true;
                // }

                let ip_u32 = u32::from_be_bytes(ip.octets());
                let addr_u32 = u32::from_be_bytes(addr.octets());
                let mask_u32 = u32::from_be_bytes(netmask.octets());

                mask_u32 & ip_u32 == mask_u32 & addr_u32
            }

            Self::Inet6 {
                addr, prefixlen, ..
            } if ip.is_ipv6() => {
                let ip = if let IpAddr::V6(v) = ip {
                    v
                } else {
                    unreachable!()
                };

                let ip_u128 = u128::from_be_bytes(ip.octets());
                let addr_u128 = u128::from_be_bytes(addr.octets());
                let mask_u128 = !(u128::MAX << (128 - prefixlen));
                mask_u128 & ip_u128 == mask_u128 & addr_u128
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
            Self::Ether { addr } => write!(f, "ether {}", addr),
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

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;

    #[test]
    fn singular_addr_space_v4() {
        let iface = InterfaceAddr::Inet {
            addr: [192, 168, 2, 110].into(),
            netmask: [255, 255, 255, 255].into(),
        };

        assert_eq!(
            iface.matches_ip_subnet(IpAddr::from_str("192.168.2.110").unwrap()),
            true
        );
        assert_eq!(
            iface.matches_ip_subnet(IpAddr::from_str("192.168.2.111").unwrap()),
            false
        );
        assert_eq!(
            iface.matches_ip_subnet(
                Ipv4Addr::from_str("192.168.2.110")
                    .unwrap()
                    .to_ipv6_compatible()
                    .into()
            ),
            false
        );
        assert_eq!(
            iface.matches_ip_subnet(
                Ipv4Addr::from_str("192.168.2.110")
                    .unwrap()
                    .to_ipv6_mapped()
                    .into()
            ),
            false
        );
    }

    #[test]
    fn loopback_namespace_v4() {
        let iface = InterfaceAddr::Inet {
            addr: [127, 0, 0, 1].into(),
            netmask: [255, 255, 255, 0].into(),
        };

        assert_eq!(
            iface.matches_ip_subnet(IpAddr::from_str("127.0.0.1").unwrap()),
            true
        );
        assert_eq!(
            iface.matches_ip_subnet(IpAddr::from_str("127.0.0.19").unwrap()),
            true
        );
        assert_eq!(
            iface.matches_ip_subnet(IpAddr::from_str("127.0.0.255").unwrap()),
            true
        );
        assert_eq!(
            iface.matches_ip_subnet(IpAddr::from_str("192.168.2.111").unwrap()),
            false
        );
        assert_eq!(
            iface.matches_ip_subnet(
                Ipv4Addr::from_str("127.0.0.19")
                    .unwrap()
                    .to_ipv6_compatible()
                    .into()
            ),
            false
        );
        assert_eq!(
            iface.matches_ip_subnet(
                Ipv4Addr::from_str("127.0.0.19")
                    .unwrap()
                    .to_ipv6_mapped()
                    .into()
            ),
            false
        );
    }

    #[test]
    fn broadcast_v4() {
        let iface = InterfaceAddr::Inet {
            addr: [192, 168, 2, 110].into(),
            netmask: [255, 255, 255, 255].into(),
        };

        assert_eq!(
            iface.matches_ip_subnet(IpAddr::from_str("255.255.255.255").unwrap()),
            true
        );

        assert_eq!(
            iface.matches_ip_subnet(IpAddr::from_str("fe::80").unwrap()),
            false
        );
    }
}
