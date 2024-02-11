use std::{
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    ops,
    time::Duration,
};

use des::time::SimTime;
use inet_types::{iface::MacAddress, ip::Ipv6AddrExt};

use crate::ipv6::addrs::CanidateAddr;

use super::IfId;

#[derive(Debug, Clone)]
pub struct InterfaceAddrs {
    pub(super) addrs: Vec<InterfaceAddr>,
    pub(super) v6_multicast: Vec<InterfaceAddrV6>,
}

impl InterfaceAddrs {
    pub fn new(addrs: Vec<InterfaceAddr>) -> Self {
        Self {
            addrs,
            v6_multicast: Vec::new(),
        }
    }

    pub fn add(&mut self, addr: InterfaceAddr) {
        assert!(
            !self.addrs.contains(&addr),
            "cannot assign address twice: {addr}"
        );
        self.addrs.push(addr);
    }

    pub fn join(&mut self, addr: InterfaceAddrV6) {
        if !self
            .v6_multicast
            .iter()
            .any(|binding| binding.addr == addr.addr)
        {
            tracing::trace!("joining multicast scope '{addr}'");
            self.v6_multicast.push(addr);
        }
    }

    pub fn ipv6_addrs(&self) -> Vec<Ipv6Addr> {
        self.addrs
            .iter()
            .filter_map(|addr| {
                if let InterfaceAddr::Inet6(addr) = addr {
                    Some(addr.addr)
                } else {
                    None
                }
            })
            .collect()
    }
}

impl ops::Deref for InterfaceAddrs {
    type Target = [InterfaceAddr];
    fn deref(&self) -> &Self::Target {
        &self.addrs
    }
}

impl ops::DerefMut for InterfaceAddrs {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.addrs
    }
}

impl FromIterator<InterfaceAddr> for InterfaceAddrs {
    fn from_iter<T: IntoIterator<Item = InterfaceAddr>>(iter: T) -> Self {
        InterfaceAddrs {
            addrs: iter.into_iter().collect(),
            v6_multicast: Vec::new(),
        }
    }
}

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
    Inet6(InterfaceAddrV6),
}

impl InterfaceAddr {
    /// Returns the addrs for a loopback interface.
    pub fn loopback() -> [Self; 2] {
        [
            InterfaceAddr::Inet {
                addr: Ipv4Addr::LOCALHOST,
                netmask: Ipv4Addr::new(255, 255, 255, 0),
            },
            InterfaceAddr::Inet6(InterfaceAddrV6::LOCALHOST),
        ]
    }

    pub fn ipv6_link_local(mac: MacAddress) -> Self {
        Self::Inet6(InterfaceAddrV6::new_link_local(mac))
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
            InterfaceAddr::Inet6(InterfaceAddrV6::new_static(v6, 64)),
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
            Self::Inet6(inet6) => match ip {
                IpAddr::V4(_) => false,
                IpAddr::V6(addr) => inet6.matches(addr),
            },
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

            Self::Inet6(inet6) => match ip {
                IpAddr::V4(_) => false,
                IpAddr::V6(addr) => inet6.matches_subnet(addr),
            },
            _ => false,
        }
    }
}

impl fmt::Display for InterfaceAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            Self::Ether { addr } => write!(f, "ether {}", addr),
            Self::Inet { addr, netmask } => write!(f, "inet {} netmask {}", addr, netmask),
            Self::Inet6(inet6) => inet6.fmt(f),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct InterfaceAddrV6 {
    pub addr: Ipv6Addr,
    pub mask: Ipv6Addr,
    pub deadline: SimTime,
    pub validity: Duration,
    pub flags: InterfaceAddrV6Flags,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct InterfaceAddrV6Flags {
    pub temporary: bool,
    pub home_addr: bool,
    pub care_of_addr: bool,
}

impl InterfaceAddrV6 {
    const LOCALHOST: InterfaceAddrV6 = InterfaceAddrV6 {
        addr: Ipv6Addr::LOCALHOST,
        mask: Ipv6Addr::new(
            0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff,
        ),
        deadline: SimTime::MAX,
        validity: Duration::MAX,
        flags: InterfaceAddrV6Flags {
            temporary: false,
            home_addr: false,
            care_of_addr: false,
        },
    };

    pub const MULTICAST_ALL_NODES: InterfaceAddrV6 = InterfaceAddrV6 {
        addr: Ipv6Addr::MULTICAST_ALL_NODES,
        mask: Ipv6Addr::ONES,
        deadline: SimTime::MAX,
        validity: Duration::MAX,
        flags: InterfaceAddrV6Flags {
            temporary: false,
            home_addr: false,
            care_of_addr: false,
        },
    };

    pub const MULTICAST_ALL_ROUTERS: InterfaceAddrV6 = InterfaceAddrV6 {
        addr: Ipv6Addr::MULTICAST_ALL_ROUTERS,
        mask: Ipv6Addr::ONES,
        deadline: SimTime::MAX,
        validity: Duration::MAX,
        flags: InterfaceAddrV6Flags {
            temporary: false,
            home_addr: false,
            care_of_addr: false,
        },
    };

    pub fn solicited_node_multicast(addr: Ipv6Addr) -> Self {
        Self::new_static(Ipv6Addr::solicied_node_multicast(addr), 128)
    }

    pub fn new_static(addr: Ipv6Addr, prefixlen: usize) -> Self {
        Self {
            addr,
            mask: Ipv6Addr::from(u128::MAX << (128 - prefixlen)),
            deadline: SimTime::MAX,
            validity: Duration::MAX,
            flags: InterfaceAddrV6Flags {
                temporary: false,
                home_addr: false,
                care_of_addr: false,
            },
        }
    }

    pub fn new_link_local(mac: MacAddress) -> Self {
        Self::new_static(mac.embed_into(Ipv6Addr::LINK_LOCAL), 64)
    }

    pub fn remaining(&self) -> Duration {
        self.deadline.duration_since(SimTime::now())
    }

    pub fn prefix_len(&self) -> u32 {
        u128::from(self.mask).leading_ones()
    }

    pub fn to_canidate_addr(&self, ifid: IfId) -> CanidateAddr {
        let remaining_lifetime = self.remaining().as_secs_f64();
        let close_to_invalidation = remaining_lifetime < 0.1 * self.validity.as_secs_f64();

        CanidateAddr {
            addr: self.addr,
            ifid,
            preferred: !close_to_invalidation,
            deprecated: close_to_invalidation,
            temporary: self.flags.temporary,
            home_addr: self.flags.home_addr,
            care_of_addr: self.flags.care_of_addr,
        }
    }

    /// Whethe `addr` is destined for this interface
    pub fn matches(&self, addr: Ipv6Addr) -> bool {
        addr == self.addr
    }

    /// Whether `addr` is contained in the same prefix as this interface.
    pub fn matches_subnet(&self, addr: Ipv6Addr) -> bool {
        let mask = u128::from(self.mask);
        let target = u128::from(self.addr);
        let addr = u128::from(addr);
        target & mask == target & addr
    }
}

impl fmt::Display for InterfaceAddrV6 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "inet6 {} prefixlen {}", self.addr, self.prefix_len(),)?;
        if self.flags.temporary {
            write!(f, " (temporary)")?;
        }
        if self.flags.home_addr && self.flags.care_of_addr {
            write!(f, " (home-addr)")?;
        } else if self.flags.care_of_addr {
            write!(f, " (care-of-addr)")?;
        }
        Ok(())
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
