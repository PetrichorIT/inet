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

#[derive(Debug, Clone, Default)]
pub struct InterfaceAddrs {
    pub(crate) v4: InterfaceAddrsV4,
    pub(crate) v6: InterfaceAddrsV6,
}

#[derive(Debug, Clone, Default)]
pub struct InterfaceAddrsV4 {
    pub(super) bindings: Vec<InterfaceAddrV4>,
}

#[derive(Debug, Clone, Default)]
pub struct InterfaceAddrsV6 {
    pub(super) unicast: Vec<InterfaceAddrV6>,
    pub(super) multicast: Vec<(Ipv6Addr, MacAddress)>,
}

impl InterfaceAddrs {
    pub fn new(addrs: Vec<InterfaceAddr>) -> Self {
        let mut this = Self::default();
        for binding in addrs {
            match binding {
                InterfaceAddr::Inet(binding) => this.v4.add(binding),
                InterfaceAddr::Inet6(binding) => this.v6.add(binding),
            }
        }

        this
    }

    pub fn add(&mut self, binding: InterfaceAddr) {
        match binding {
            InterfaceAddr::Inet(binding) => self.v4.add(binding),
            InterfaceAddr::Inet6(binding) => self.v6.add(binding),
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = InterfaceAddr> + '_ {
        self.v4
            .bindings
            .iter()
            .map(|binding| InterfaceAddr::Inet(binding.clone()))
            .chain(
                self.v6
                    .unicast
                    .iter()
                    .map(|binding| InterfaceAddr::Inet6(binding.clone())),
            )
    }

    pub fn multicast_scopes(&self) -> &[(Ipv6Addr, MacAddress)] {
        &self.v6.multicast[..]
    }
}

impl InterfaceAddrsV4 {
    pub fn add(&mut self, unicast: InterfaceAddrV4) {
        assert!(
            !self.bindings.contains(&unicast),
            "cannot assign ipv6 binding '{unicast}': address allready assigned"
        );
        assert!(
            !unicast.addr.is_multicast(),
            "cannot assign ipv6 binding '{unicast}': address is multicast scope"
        );
        self.bindings.push(unicast);
    }

    pub fn matches(&self, dst: Ipv4Addr) -> bool {
        self.bindings.iter().any(|binding| binding.matches(dst))
    }
}

impl InterfaceAddrsV6 {
    pub fn add(&mut self, unicast: InterfaceAddrV6) {
        assert!(
            !self.unicast.contains(&unicast),
            "cannot assign ipv6 binding '{unicast}': address allready assigned"
        );
        assert!(
            !unicast.addr.is_multicast(),
            "cannot assign ipv6 binding '{unicast}': address is multicast scope"
        );
        self.unicast.push(unicast);
    }

    pub fn join(&mut self, multicast: Ipv6Addr) {
        assert!(
            multicast.is_multicast(),
            "cannot join multicast group '{multicast}': address is not multicast"
        );
        self.multicast
            .push((multicast, MacAddress::ipv6_multicast(multicast)));
    }

    /// The bound unicast addrs
    pub fn addrs(&self) -> impl Iterator<Item = Ipv6Addr> + '_ {
        self.unicast.iter().map(|binding| binding.addr)
    }

    pub fn valid_src_mac(&self, addr: MacAddress) -> bool {
        self.multicast.iter().any(|(_, binding)| *binding == addr)
    }

    /// Whether the bindings of this interface can be used as a receiver
    /// for a packet addressed to `dst`
    pub fn matches(&self, dst: Ipv6Addr) -> bool {
        if dst.is_multicast() {
            self.multicast
                .iter()
                .any(|(multicast, _)| *multicast == dst)
        } else {
            self.unicast.iter().any(|binding| binding.matches(dst))
        }
    }

    /// Whether `dst` is contained in a bound subnet.
    pub fn matches_subnet(&self, dst: Ipv6Addr) -> bool {
        if dst.is_multicast() {
            true
        } else {
            self.unicast
                .iter()
                .any(|binding| binding.matches_subnet(dst))
        }
    }
}

impl FromIterator<InterfaceAddr> for InterfaceAddrs {
    fn from_iter<T: IntoIterator<Item = InterfaceAddr>>(iter: T) -> Self {
        let addrs = iter.into_iter().collect::<Vec<_>>();
        Self::new(addrs)
    }
}

/// A interface addr.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum InterfaceAddr {
    /// An Ipv4 declaration
    Inet(InterfaceAddrV4),
    /// The Ipv6 declaration
    Inet6(InterfaceAddrV6),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct InterfaceAddrV4 {
    pub addr: Ipv4Addr,
    pub netmask: Ipv4Addr,
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

impl InterfaceAddr {
    /// Returns the addrs for a loopback interface.
    pub const LOOPBACK: [Self; 2] = [
        InterfaceAddr::Inet(InterfaceAddrV4::LOCALHOST),
        InterfaceAddr::Inet6(InterfaceAddrV6::LOCALHOST),
    ];

    pub fn ipv6_link_local(mac: MacAddress) -> Self {
        Self::Inet6(InterfaceAddrV6::new_link_local(mac))
    }

    /// Returns the addrs for a loopback interface.
    pub fn en0(v4: Ipv4Addr) -> [Self; 2] {
        let v6 = v4.to_ipv6_compatible();
        [
            InterfaceAddr::Inet(InterfaceAddrV4 {
                addr: v4,
                netmask: Ipv4Addr::new(255, 255, 255, 0),
            }),
            InterfaceAddr::Inet6(InterfaceAddrV6::new_static(v6, 64)),
        ]
    }

    pub fn matches(&self, dst: IpAddr) -> bool {
        match (dst, self) {
            (IpAddr::V4(dst), InterfaceAddr::Inet(binding)) => binding.matches(dst),
            (IpAddr::V6(dst), InterfaceAddr::Inet6(binding)) => binding.matches(dst),
            _ => false,
        }
    }

    pub fn matches_subnet(&self, dst: IpAddr) -> bool {
        match (dst, self) {
            (IpAddr::V4(dst), InterfaceAddr::Inet(binding)) => binding.matches_subnet(dst),
            (IpAddr::V6(dst), InterfaceAddr::Inet6(binding)) => binding.matches_subnet(dst),
            _ => false,
        }
    }
}

impl InterfaceAddrV4 {
    pub const LOCALHOST: InterfaceAddrV4 = InterfaceAddrV4 {
        addr: Ipv4Addr::LOCALHOST,
        netmask: Ipv4Addr::new(255, 255, 255, 0),
    };

    pub fn new(addr: Ipv4Addr, netmask: Ipv4Addr) -> InterfaceAddrV4 {
        Self { addr, netmask }
    }

    pub fn matches(&self, dst: Ipv4Addr) -> bool {
        if dst.is_broadcast() {
            true
        } else {
            dst == self.addr
        }
    }

    pub fn matches_subnet(&self, dst: Ipv4Addr) -> bool {
        if dst.is_broadcast() {
            true
        } else {
            let ip_u32 = u32::from_be_bytes(dst.octets());
            let addr_u32 = u32::from_be_bytes(self.addr.octets());
            let mask_u32 = u32::from_be_bytes(self.netmask.octets());

            mask_u32 & ip_u32 == mask_u32 & addr_u32
        }
    }
}

impl InterfaceAddrV6 {
    pub const LOCALHOST: InterfaceAddrV6 = InterfaceAddrV6 {
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

impl ops::Deref for InterfaceAddrsV4 {
    type Target = [InterfaceAddrV4];
    fn deref(&self) -> &Self::Target {
        &self.bindings
    }
}

impl ops::Deref for InterfaceAddrsV6 {
    type Target = [InterfaceAddrV6];
    fn deref(&self) -> &Self::Target {
        &self.unicast
    }
}

impl fmt::Display for InterfaceAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            Self::Inet(inet4) => inet4.fmt(f),
            Self::Inet6(inet6) => inet6.fmt(f),
        }
    }
}

impl fmt::Display for InterfaceAddrV4 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "inet {} netmask {}", self.addr, self.netmask)
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
        let iface = InterfaceAddr::Inet(InterfaceAddrV4::new(
            Ipv4Addr::new(192, 168, 2, 110),
            Ipv4Addr::BROADCAST,
        ));

        assert_eq!(
            iface.matches_subnet(Ipv4Addr::new(192, 168, 2, 110).into()),
            true
        );
        assert_eq!(
            iface.matches_subnet(Ipv4Addr::new(192, 168, 2, 111).into()),
            false
        );
        assert_eq!(
            iface.matches_subnet(Ipv4Addr::new(192, 168, 2, 110).to_ipv6_compatible().into()),
            false
        );
        assert_eq!(
            iface.matches_subnet(Ipv4Addr::new(192, 168, 2, 110).to_ipv6_mapped().into()),
            false
        );
    }

    #[test]
    fn loopback_namespace_v4() {
        let iface = InterfaceAddr::Inet(InterfaceAddrV4::new(
            Ipv4Addr::LOCALHOST,
            Ipv4Addr::new(255, 255, 255, 0),
        ));

        assert_eq!(iface.matches_subnet(Ipv4Addr::LOCALHOST.into()), true);
        assert_eq!(
            iface.matches_subnet(Ipv4Addr::new(127, 0, 0, 19).into()),
            true
        );
        assert_eq!(
            iface.matches_subnet(Ipv4Addr::new(127, 0, 0, 255).into()),
            true
        );
        assert_eq!(
            iface.matches_subnet(Ipv4Addr::new(192, 168, 2, 111).into()),
            false
        );
        assert_eq!(
            iface.matches_subnet(Ipv4Addr::new(127, 0, 0, 19).to_ipv6_compatible().into()),
            false
        );
        assert_eq!(
            iface.matches_subnet(Ipv4Addr::new(127, 0, 0, 19).to_ipv6_mapped().into()),
            false
        );
    }

    #[test]
    fn broadcast_v4() {
        let iface = InterfaceAddr::Inet(InterfaceAddrV4::new(
            Ipv4Addr::new(192, 168, 2, 110),
            Ipv4Addr::BROADCAST,
        ));

        assert_eq!(iface.matches_subnet(Ipv4Addr::BROADCAST.into()), true);

        assert_eq!(
            iface.matches_subnet(IpAddr::from_str("fe80::").unwrap()),
            false
        );
    }
}
