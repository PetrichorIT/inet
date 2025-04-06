use std::{
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::Duration,
};

use des::{net::module::try_current, prelude::current, time::SimTime};
use types::{iface::MacAddress, ip::Ipv6AddrExt};

use crate::ipv6::addrs::CanidateAddr;

use super::IfId;

#[derive(Debug, Clone, Default)]
pub struct InterfaceAddrBindings {
    pub v4: InterfaceAddrsV4,
    pub v6: InterfaceAddrsV6,
}

#[derive(Debug, Clone, Default)]
pub struct InterfaceAddrsV4 {
    pub unicast: Vec<InterfaceAddrV4>,
}

#[derive(Debug, Clone, Default)]
pub struct InterfaceAddrsV6 {
    pub unicast: Vec<InterfaceAddrV6>,
    pub multicast: Vec<Ipv6Addr>,
    pub recv_all_multicast: bool,
}

impl InterfaceAddrBindings {
    pub fn addrs(&self) -> impl Iterator<Item = IpAddr> + '_ {
        self.v4
            .unicast
            .iter()
            .map(|binding| binding.addr.into())
            .chain(self.v6.unicast.iter().map(|binding| binding.addr.into()))
    }

    pub fn has_v4_capability(&self) -> bool {
        !self.v4.unicast.is_empty()
    }

    pub fn has_v6_capability(&self) -> bool {
        !self.v6.unicast.is_empty()
    }

    pub fn matches(&self, dst: IpAddr) -> bool {
        match dst {
            IpAddr::V4(addr) => self.v4.matches(addr),
            IpAddr::V6(addr) => self.v6.matches(addr),
        }
    }

    pub fn multicast_scopes(&self) -> &[Ipv6Addr] {
        &self.v6.multicast[..]
    }
}

impl InterfaceAddrsV4 {
    pub fn add(&mut self, unicast: InterfaceAddrV4) {
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

    pub fn matches(&self, dst: Ipv4Addr) -> bool {
        self.unicast.iter().any(|binding| binding.matches(dst))
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

        // try_current so that we can test without a module context present
        if let Some(Ok(mut addrs)) = try_current().map(|c| c.prop::<Vec<Ipv6Addr>>("inet.addrs.v6"))
        {
            addrs.or_default().update(|addrs| addrs.push(unicast.addr));
        }

        self.unicast.push(unicast);
    }

    pub fn remove(&mut self, addr: Ipv6Addr) -> Option<InterfaceAddrV6> {
        for i in 0..self.unicast.len() {
            if self.unicast[i].matches(addr) {
                let addr = self.unicast.remove(i);
                tracing::debug!(%addr, "unassigning unicast address");

                if let Ok(mut addrs) = current().prop::<Vec<Ipv6Addr>>("inet.addrs.v6") {
                    addrs
                        .or_default()
                        .update(|addrs| addrs.retain(|a| *a != addr.addr));
                }

                return Some(addr);
            }
        }
        None
    }

    /// Returns needs adv
    pub fn join(&mut self, multicast: Ipv6Addr) -> bool {
        assert!(
            multicast.is_multicast(),
            "cannot join multicast group '{multicast}': address is not multicast"
        );
        if !self.multicast.iter().any(|addr| *addr == multicast) {
            self.multicast.push(multicast);
            true
        } else {
            false
        }
    }

    pub fn leave(&mut self, multicast: Ipv6Addr) {
        // TODO: same sol scope may attend to multile unicast -> only del after last unicast
        tracing::debug!(addr = %multicast, "leaving multicast scope");
        self.multicast.retain(|addr| *addr != multicast);
    }

    /// The bound unicast addrs
    pub fn addrs(&self) -> impl Iterator<Item = Ipv6Addr> + '_ {
        self.unicast.iter().map(|binding| binding.addr)
    }

    pub fn valid_src_mac(&self, mac_addr: MacAddress) -> bool {
        (self.recv_all_multicast && mac_addr.is_multicast())
            || self
                .multicast
                .iter()
                .any(|addr| MacAddress::ipv6_multicast(*addr) == mac_addr)
    }

    /// Whether the bindings of this interface can be used as a receiver
    /// for a packet addressed to `dst`
    pub fn matches(&self, dst: Ipv6Addr) -> bool {
        if dst.is_multicast() {
            self.recv_all_multicast || self.multicast.iter().any(|multicast| *multicast == dst)
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

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct InterfaceAddrV4 {
    pub addr: Ipv4Addr,
    pub mask: Ipv4Addr,
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

impl InterfaceAddrV4 {
    pub fn new(addr: Ipv4Addr, netmask: Ipv4Addr) -> InterfaceAddrV4 {
        Self {
            addr,
            mask: netmask,
        }
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
            let mask_u32 = u32::from_be_bytes(self.mask.octets());

            mask_u32 & ip_u32 == mask_u32 & addr_u32
        }
    }
}

impl InterfaceAddrV6 {
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

impl fmt::Display for InterfaceAddrV4 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "inet {} netmask {}", self.addr, self.mask)
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
    use super::*;

    #[test]
    fn singular_addr_space_v4() {
        let iface = InterfaceAddrV4::new(Ipv4Addr::new(192, 168, 2, 110), Ipv4Addr::BROADCAST);

        assert_eq!(
            iface.matches_subnet(Ipv4Addr::new(192, 168, 2, 110).into()),
            true
        );
        assert_eq!(
            iface.matches_subnet(Ipv4Addr::new(192, 168, 2, 111).into()),
            false
        );
    }

    #[test]
    fn loopback_namespace_v4() {
        let iface = InterfaceAddrV4::new(Ipv4Addr::LOCALHOST, Ipv4Addr::new(255, 255, 255, 0));

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
    }

    #[test]
    fn broadcast_v4() {
        let iface = InterfaceAddrV4::new(Ipv4Addr::new(192, 168, 2, 110), Ipv4Addr::BROADCAST);
        assert_eq!(iface.matches_subnet(Ipv4Addr::BROADCAST.into()), true);
    }
}
