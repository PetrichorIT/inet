//! IPv6 address configuration and utility types (RFC 6724)
//!
//! May be important:
//! - RFC 4862
//! - RFC 4291
//! - RFC 8028
//! - RFC 6204
//! - RFC 5942

use std::{
    cmp::Ordering,
    net::{IpAddr, Ipv6Addr},
    ops,
    str::FromStr,
};

use crate::{ctx::IOContext, interface::IfId};
use inet_types::ip::{Ipv6AddrExt, Ipv6LongestPrefixTable, Ipv6Prefix};

mod api;
pub use api::*;

pub struct PolicyTable {
    table: Ipv6LongestPrefixTable<PolicyEntry>,
}

struct PolicyEntry {
    precedence: usize,
    label: usize,
}

impl PolicyTable {
    fn add(&mut self, prefix: Ipv6Prefix, precedence: usize, label: usize) {
        self.table.insert(prefix, PolicyEntry { precedence, label });
    }

    fn remove(&mut self, prefix: Ipv6Prefix) {
        self.table.remove(prefix);
    }

    fn lookup(&self, addr: Ipv6Addr) -> Option<&PolicyEntry> {
        self.table.lookup(addr)
    }
}

impl Default for PolicyTable {
    fn default() -> Self {
        let mut table = Ipv6LongestPrefixTable::new();
        table.insert(
            Ipv6Prefix::new(Ipv6Addr::LOCALHOST, 128),
            PolicyEntry {
                precedence: 50,
                label: 0,
            },
        );
        table.insert(
            Ipv6Prefix::new(Ipv6Addr::UNSPECIFIED, 0),
            PolicyEntry {
                precedence: 40,
                label: 1,
            },
        );
        table.insert(
            Ipv6Prefix::new(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0, 0), 96),
            PolicyEntry {
                precedence: 35,
                label: 4,
            },
        );
        table.insert(
            Ipv6Prefix::new(Ipv6Addr::new(0x2002, 0, 0, 0, 0, 0, 0, 0), 16),
            PolicyEntry {
                precedence: 30,
                label: 2,
            },
        );
        table.insert(
            Ipv6Prefix::new(Ipv6Addr::new(0x2001, 0, 0, 0, 0, 0, 0, 0), 32),
            PolicyEntry {
                precedence: 5,
                label: 5,
            },
        );
        table.insert(
            Ipv6Prefix::new(Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 0), 7),
            PolicyEntry {
                precedence: 3,
                label: 13,
            },
        );
        table.insert(
            Ipv6Prefix::new(Ipv6Addr::UNSPECIFIED, 96),
            PolicyEntry {
                precedence: 1,
                label: 3,
            },
        );
        table.insert(
            Ipv6Prefix::new(Ipv6Addr::new(0xfec0, 0, 0, 0, 0, 0, 0, 0), 10),
            PolicyEntry {
                precedence: 1,
                label: 11,
            },
        );
        table.insert(
            Ipv6Prefix::new(Ipv6Addr::new(0x3ffe, 0, 0, 0, 0, 0, 0, 0), 16),
            PolicyEntry {
                precedence: 1,
                label: 12,
            },
        );
        Self { table }
    }
}

#[derive(Debug, Clone)]
pub(super) struct SrcAddrCanidateSet {
    addrs: Vec<CanidateAddr>,
    dst: Ipv6Addr,
    ifid: IfId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CanidateAddr {
    pub addr: Ipv6Addr,
    pub ifid: IfId,
    pub preferred: bool,  // according to RFC 4862
    pub deprecated: bool, // according to RFC 4862
    pub temporary: bool,
    pub home_addr: bool,
    pub care_of_addr: bool,
}

impl CanidateAddr {
    pub const UNSPECIFED: CanidateAddr = CanidateAddr {
        addr: Ipv6Addr::UNSPECIFIED,
        ifid: IfId::NULL,
        preferred: false,
        deprecated: false,
        temporary: false,
        home_addr: false,
        care_of_addr: false,
    };
}

impl ops::Deref for CanidateAddr {
    type Target = Ipv6Addr;
    fn deref(&self) -> &Self::Target {
        &self.addr
    }
}

impl FromStr for CanidateAddr {
    type Err = &'static str;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut parts = s.split(" ");
        let addr: IpAddr = parts
            .next()
            .ok_or("cannot find addr part")?
            .parse()
            .map_err(|_| "addr parsing error")?;

        let addr = match addr {
            IpAddr::V4(v4) => v4.to_ipv6_mapped(),
            IpAddr::V6(v6) => v6,
        };

        let mut canidate = CanidateAddr {
            addr,
            ifid: IfId::NULL,
            preferred: addr.to_ipv4().is_some(),
            deprecated: false,
            temporary: false,
            home_addr: false,
            care_of_addr: false,
        };

        for part in parts {
            if part.starts_with('#') {
                let iface = IfId::new(part.trim_start_matches('#'));
                canidate.ifid = iface;
                continue;
            }

            match part {
                "(temporary)" => canidate.temporary = true,
                "(perferred)" => canidate.preferred = true,
                "(deprecated)" => canidate.deprecated = true,
                "(care-of-addr)" => canidate.care_of_addr = true,
                "(home-addr)" => canidate.home_addr = true,
                _ => todo!(),
            }
        }

        Ok(canidate)
    }
}

impl IOContext {
    // pub(super) fn ipv6_src_addr_canidate_set_for_socket(
    //     &self,
    //     socket: &Socket,
    //     dst: Ipv6Addr,
    // ) -> SrcAddrCanidateSet {
    //     let ifid = socket.interface.unwrap_ifid();
    //     let mut set = self.ipv6_src_addr_canidate_set(dst, ifid);
    //     if let IpAddr::V6(addr) = socket.addr.ip() {
    //         if !addr.is_unspecified() {
    //             set.addrs.retain(|canidate| canidate.addr == addr);
    //         }
    //     }
    //     set
    // }

    pub(super) fn ipv6_src_addr_canidate_set(
        &self,
        dst: Ipv6Addr,
        preferred_iface: IfId,
    ) -> SrcAddrCanidateSet {
        let mut addrs = if preferred_iface == IfId::NULL {
            // any interface
            let mut addrs = Vec::new();
            for (ifid, iface) in &self.ifaces {
                for addr in iface.addrs.v6.addrs() {
                    addrs.push(CanidateAddr {
                        addr: addr,
                        ifid: *ifid,
                        preferred: false,
                        deprecated: false,
                        temporary: false,
                        home_addr: false,
                        care_of_addr: false,
                    });
                }
            }
            addrs
        } else {
            let iface = self.ifaces.get(&preferred_iface).unwrap();
            iface
                .addrs
                .v6
                .addrs()
                .map(|v| CanidateAddr {
                    addr: v,
                    ifid: preferred_iface,
                    preferred: false,
                    deprecated: false,
                    temporary: false,
                    home_addr: false,
                    care_of_addr: false,
                })
                .collect()
        };

        // TODO:
        // for multicast addrs or site local stuff, iface limitations

        // For site local dst:
        // Only include addrs assigned to the interface facing this site
        if preferred_iface != IfId::NULL {
            addrs.retain(|canidate| canidate.ifid == preferred_iface);
        }

        SrcAddrCanidateSet::new(addrs, dst, preferred_iface)
    }
}

impl SrcAddrCanidateSet {
    pub(super) fn new(addrs: Vec<CanidateAddr>, dst: Ipv6Addr, ifid: IfId) -> Self {
        Self { addrs, dst, ifid }
    }

    pub(super) fn select(&self, policies: &PolicyTable) -> Option<CanidateAddr> {
        self.addrs
            .iter()
            .max_by(|&&sa, &&sb| {
                // Sorting according to RFC 6724

                // Rule 0: use respect ip version
                let sa_is_ipv4 = sa.to_ipv4().is_some();
                let sb_is_ipv4 = sb.to_ipv4().is_some();
                let dst_is_ipv4 = self.dst.to_ipv4().is_some();

                if sa_is_ipv4 == dst_is_ipv4 && sb_is_ipv4 != dst_is_ipv4 {
                    return Ordering::Greater;
                }
                if sb_is_ipv4 == dst_is_ipv4 && sa_is_ipv4 != dst_is_ipv4 {
                    return Ordering::Less;
                }

                // Rule 1: Same address preference
                if sa.addr == self.dst {
                    return Ordering::Greater;
                }
                if sb.addr == self.dst {
                    return Ordering::Less;
                }

                // Rule 2: prefer appropiate scope
                if sa.scope() < sb.scope() {
                    if sa.scope() < self.dst.scope() {
                        return Ordering::Less;
                    } else {
                        return Ordering::Greater;
                    }
                }

                if sb.scope() < sa.scope() {
                    if sb.scope() < self.dst.scope() {
                        return Ordering::Greater;
                    } else {
                        return Ordering::Less;
                    }
                }

                // Rule 3: avoid deprecated addrs
                if sa.deprecated && !sb.deprecated {
                    return Ordering::Less;
                }
                if sb.deprecated && !sa.deprecated {
                    return Ordering::Greater;
                }

                // Rule 4: prefer home addr
                if sa.home_addr && sa.care_of_addr && !(sb.home_addr && sb.care_of_addr) {
                    return Ordering::Greater;
                }
                if sb.home_addr && sb.care_of_addr && !(sa.home_addr && sa.care_of_addr) {
                    return Ordering::Less;
                }

                // Rule 5: prefer outgoing iface
                if self.ifid == sa.ifid && self.ifid != sb.ifid {
                    return Ordering::Greater;
                }

                if self.ifid == sb.ifid && self.ifid != sa.ifid {
                    return Ordering::Less;
                }

                // Rule 5.5: prefered advertised next hops
                // TODO: impl

                // Rule 6:
                if let (Some(ap), Some(bp), Some(dstp)) = (
                    policies.lookup(sa.addr),
                    policies.lookup(sb.addr),
                    policies.lookup(self.dst),
                ) {
                    if ap.label == dstp.label && bp.label != dstp.label {
                        return Ordering::Greater;
                    }

                    if bp.label == dstp.label && ap.label != dstp.label {
                        return Ordering::Less;
                    }
                }

                // Rule 7: Prefer temporary addrs
                if sa.temporary && !sb.temporary {
                    return Ordering::Greater;
                }
                if sb.temporary && !sa.temporary {
                    return Ordering::Less;
                }

                // Rule 8: longes prefix match
                // TODO: prefix len info must be stored with the canidate set
                let a_prefix = Ipv6Prefix::fit(sa.addr);
                let b_prefix = Ipv6Prefix::fit(sb.addr);
                match a_prefix
                    .common_prefix_len(self.dst)
                    .cmp(&b_prefix.common_prefix_len(self.dst))
                {
                    Ordering::Equal => {}
                    other => return other,
                }

                Ordering::Equal
            })
            .cloned()
    }
}

#[derive(Debug, Clone)]
pub(super) struct AddrSelection {
    destinations: Vec<(Ipv6Addr, CanidateAddr, SrcAddrCanidateSet)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Selection {
    src: Ipv6Addr,
    src_ifid: IfId,
    dst: Ipv6Addr,
}

impl AddrSelection {
    fn new(destinations: Vec<Ipv6Addr>, f: impl Fn(Ipv6Addr) -> SrcAddrCanidateSet) -> Self {
        AddrSelection {
            destinations: destinations
                .into_iter()
                .map(|dst| (dst, CanidateAddr::UNSPECIFED, f(dst)))
                .collect(),
        }
    }

    fn new_with_static(destinations: Vec<Ipv6Addr>, src_set: Vec<CanidateAddr>) -> Self {
        AddrSelection {
            destinations: destinations
                .into_iter()
                .map(|dst| {
                    (
                        dst,
                        CanidateAddr::UNSPECIFED,
                        SrcAddrCanidateSet {
                            addrs: src_set.clone(),
                            dst,
                            ifid: IfId::NULL,
                        },
                    )
                })
                .collect(),
        }
    }

    fn select_all(&mut self, policies: &PolicyTable) -> Vec<Selection> {
        let mut selections = Vec::new();
        while let Some(selection) = self.select(policies) {
            selections.push(selection);
        }
        selections
    }

    fn select(&mut self, policies: &PolicyTable) -> Option<Selection> {
        self.destinations.iter_mut().for_each(|tupel| {
            tupel.1 = tupel.2.select(policies).unwrap_or(CanidateAddr::UNSPECIFED)
        });

        self.destinations
            .extract_max_by(|&(da, sa, _), &(db, sb, _)| {
                // Rule 1: Avoid unstable addrs
                // TODO: lookup in destination cache
                // TODO: src addrs checks

                // Rule 2: Prefer matching scope

                if da.scope() == sa.scope() && db.scope() != sb.scope() {
                    return Ordering::Greater;
                }
                if db.scope() == sb.scope() && da.scope() != sa.scope() {
                    return Ordering::Less;
                }

                // Rule 3: avoid depc addrs
                if sa.deprecated && !sb.deprecated {
                    return Ordering::Less;
                }
                if sb.deprecated && !sa.deprecated {
                    return Ordering::Greater;
                }

                // Rule 4: Preferm home addr (equivalent to src-addr-select)
                if sa.home_addr && sa.care_of_addr && !(sb.home_addr && sb.care_of_addr) {
                    return Ordering::Greater;
                }
                if sb.home_addr && sb.care_of_addr && !(sa.home_addr && sa.care_of_addr) {
                    return Ordering::Less;
                }
                // Rule 5: Prefer matching label
                let (Some(dap), Some(sap), Some(dbp), Some(sbp)) = (
                    policies.lookup(da),
                    policies.lookup(sa.addr),
                    policies.lookup(db),
                    policies.lookup(sb.addr),
                ) else {
                    todo!()
                };

                if sap.label == dap.label && sbp.label != dbp.label {
                    return Ordering::Greater;
                }
                if sbp.label == dbp.label && sap.label != dap.label {
                    return Ordering::Less;
                }

                // Rule 6: Prefer higher precedence
                if dap.precedence > dbp.precedence {
                    return Ordering::Greater;
                }
                if dbp.precedence > dap.precedence {
                    return Ordering::Less;
                }

                // Rule 7: prefer nativ mechanism
                // TODO: impl

                // Rule 8: Prefer small scope
                // inv ordering, since smaller scopes are prefered
                match db.scope().cmp(&da.scope()) {
                    Ordering::Equal => {}
                    other => return other,
                }

                // Rule 9: longest prefix
                let sa_prefix = Ipv6Prefix::fit(sa.addr);
                let sb_prefix = Ipv6Prefix::fit(sa.addr);

                if sa_prefix.common_prefix_len(da) > sb_prefix.common_prefix_len(db) {
                    return Ordering::Greater;
                }
                if sb_prefix.common_prefix_len(db) > sa_prefix.common_prefix_len(da) {
                    return Ordering::Greater;
                }

                Ordering::Equal
            })
            .map(|(dst, src, _)| Selection {
                src: src.addr,
                src_ifid: src.ifid,
                dst,
            })
    }
}

#[allow(unused)]
trait VecExt<T> {
    fn extract_max_by<F>(&mut self, f: F) -> Option<T>
    where
        F: FnMut(&T, &T) -> Ordering;
}

impl<T> VecExt<T> for Vec<T> {
    fn extract_max_by<F>(&mut self, mut f: F) -> Option<T>
    where
        F: FnMut(&T, &T) -> Ordering,
    {
        if self.is_empty() {
            None
        } else {
            let mut idx = 0;
            let mut max = &self[0];
            for i in 1..self.len() {
                let cur = &self[i];
                match f(max, cur) {
                    Ordering::Less => {
                        max = cur;
                        idx = i;
                    }
                    _ => {}
                }
            }
            Some(self.remove(idx))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    type Result = std::result::Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn src_addr_selection_appropiate_scope() -> Result {
        let table = PolicyTable::default();

        let set = SrcAddrCanidateSet {
            dst: "2001:db8:1::1".parse()?,
            ifid: IfId::new("eth0"),
            addrs: vec!["2001:db8:3::1 #eth0".parse()?, ("fe80::1 #eth0".parse()?)],
        };
        assert_eq!(set.select(&table), Some("2001:db8:3::1 #eth0".parse()?));

        let set = SrcAddrCanidateSet {
            dst: "ff05::1".parse()?,
            ifid: IfId::new("eth0"),
            addrs: vec![("2001:db8:3::1 #eth0".parse()?), ("fe80::1 #eth0".parse()?)],
        };
        assert_eq!(set.select(&table), Some("2001:db8:3::1 #eth0".parse()?));

        let set = SrcAddrCanidateSet {
            dst: "fe80::1".parse()?,
            ifid: IfId::new("eth0"),
            addrs: vec![("fe80::2 #eth0".parse()?), ("2001:db8:1::1 #eth0".parse()?)],
        };
        assert_eq!(set.select(&table), Some("fe80::2 #eth0".parse()?));

        Ok(())
    }

    #[test]
    fn src_addr_selection_same_addr() -> Result {
        let table = PolicyTable::default();

        let set = SrcAddrCanidateSet {
            dst: "2001:db8:1::1".parse()?,
            ifid: IfId::new("eth0"),
            addrs: vec![
                ("2001:db8:1::1 #eth0".parse()?),
                ("2001:db8:2::1 #eth0".parse()?),
            ],
        };
        assert_eq!(set.select(&table), Some("2001:db8:1::1 #eth0".parse()?));

        Ok(())
    }

    #[test]
    fn src_addr_selection_longest_prefix_match() -> Result {
        let table = PolicyTable::default();

        let set = SrcAddrCanidateSet {
            dst: "2001:db8:1::1".parse()?,
            ifid: IfId::new("eth0"),
            addrs: vec![
                ("2001:db8:1::2 #eth0".parse()?),
                ("2001:db8:3::2 #eth0".parse()?),
            ],
        };
        assert_eq!(set.select(&table), Some("2001:db8:1::2 #eth0".parse()?));

        Ok(())
    }

    #[test]
    fn src_addr_selection_matching_label() -> Result {
        let table = PolicyTable::default();

        let set = SrcAddrCanidateSet {
            dst: "2002:c633:6401::1".parse()?,
            ifid: IfId::new("eth0"),
            addrs: vec![
                ("2002:c633:6401::d5e3:7953:13eb:22e8 #eth0".parse()?),
                ("2001:db8:1::2 #eth0".parse()?),
            ],
        };
        assert_eq!(
            set.select(&table),
            Some("2002:c633:6401::d5e3:7953:13eb:22e8 #eth0".parse()?)
        );

        Ok(())
    }

    #[test]
    fn src_addr_selection_home_addr() -> Result {
        let table = PolicyTable::default();

        let set = SrcAddrCanidateSet {
            dst: "2001:db8:1::1".parse()?,
            ifid: IfId::new("eth0"),
            addrs: vec![
                ("2001:db8:1::2 #eth0 (care-of-addr)".parse()?),
                ("2001:db8:3::2 #eth0 (care-of-addr) (home-addr)".parse()?),
            ],
        };
        assert_eq!(
            set.select(&table),
            Some("2001:db8:3::2 #eth0 (care-of-addr) (home-addr)".parse()?)
        );

        Ok(())
    }

    #[test]
    fn src_addr_selection_temporary() -> Result {
        let table = PolicyTable::default();

        let set = SrcAddrCanidateSet {
            dst: "2001:db8:1::d5e3:0:0:1".parse()?,
            ifid: IfId::new("eth0"),
            addrs: vec![
                ("2001:db8:1::2 #eth0".parse()?),
                ("2001:db8:1::d5e3:7953:13eb:22e8 #eth0 (temporary)".parse()?),
            ],
        };
        assert_eq!(
            set.select(&table),
            Some("2001:db8:1::d5e3:7953:13eb:22e8 #eth0 (temporary)".parse()?)
        );

        Ok(())
    }

    #[test]
    fn dst_addr_selection_small_scope() -> Result {
        let table = PolicyTable::default();
        let mut selector = AddrSelection::new_with_static(
            vec!["2001:db8:1::1".parse()?, "fe80::1".parse()?],
            vec![("2001:db8:1::2 #en0".parse()?), ("fe80::2 #en0".parse()?)],
        );

        assert_eq!(
            selector.select_all(&table),
            [
                Selection {
                    dst: "fe80::1".parse()?,
                    src: "fe80::2".parse()?,
                    src_ifid: IfId::new("en0"),
                },
                Selection {
                    dst: "2001:db8:1::1".parse()?,
                    src: "2001:db8:1::2".parse()?,
                    src_ifid: IfId::new("en0"),
                },
            ]
        );
        Ok(())
    }

    #[test]
    fn dst_addr_selection_longest_prefix() -> Result {
        let table = PolicyTable::default();
        let mut selector = AddrSelection::new_with_static(
            vec!["2001:db8:1::1".parse()?, "2001:db8:3ffe::1".parse()?],
            vec![
                ("2001:db8:1::2 #en0".parse()?),
                ("2001:db8:3f44::2 #en0".parse()?),
                ("fe80::2 #en0".parse()?),
            ],
        );

        assert_eq!(
            selector.select_all(&table),
            [
                Selection {
                    dst: "2001:db8:1::1".parse()?,
                    src: "2001:db8:1::2".parse()?,
                    src_ifid: IfId::new("en0"),
                },
                Selection {
                    dst: "2001:db8:3ffe::1".parse()?,
                    src: "2001:db8:3f44::2".parse()?,
                    src_ifid: IfId::new("en0"),
                }
            ]
        );
        Ok(())
    }

    #[test]
    fn dst_addr_selection_matching_label() -> Result {
        let table = PolicyTable::default();
        let mut selector = AddrSelection::new_with_static(
            vec!["2002:c633:6401::1".parse()?, "2001:db8:1::1".parse()?],
            vec![
                ("2002:c633:6401::2 #en0".parse()?),
                ("fe80::2 #en0".parse()?),
            ],
        );

        assert_eq!(
            selector.select_all(&table),
            [
                Selection {
                    dst: "2002:c633:6401::1".parse()?,
                    src: "2002:c633:6401::2".parse()?,
                    src_ifid: IfId::new("en0"),
                },
                Selection {
                    dst: "2001:db8:1::1".parse()?,
                    src: "2002:c633:6401::2".parse()?,
                    src_ifid: IfId::new("en0"),
                }
            ]
        );
        Ok(())
    }

    #[test]
    fn dst_addr_selection_precedence() -> Result {
        let table = PolicyTable::default();
        let mut selector = AddrSelection::new_with_static(
            vec!["2002:c633:6401::1".parse()?, "2001:db8:1::1".parse()?],
            vec![
                ("2002:c633:6401::2 #en0".parse()?),
                ("2001:db8:1::2 #en0".parse()?),
                ("fe80::2 #en0".parse()?),
            ],
        );

        assert_eq!(
            selector.select_all(&table),
            [
                Selection {
                    dst: "2001:db8:1::1".parse()?,
                    src: "2001:db8:1::2".parse()?,
                    src_ifid: IfId::new("en0"),
                },
                Selection {
                    dst: "2002:c633:6401::1".parse()?,
                    src: "2002:c633:6401::2".parse()?,
                    src_ifid: IfId::new("en0"),
                }
            ]
        );

        let mut selector = AddrSelection::new_with_static(
            vec![
                "2001:db8:1::1".parse()?,
                "10.1.2.3".parse::<Ipv4Addr>()?.to_ipv6_mapped(),
            ],
            vec![
                ("2001:db8:1::2 #en0".parse()?),
                ("fe80::1 #en0".parse()?),
                ("10.1.2.4 #en0".parse()?),
            ],
        );

        assert_eq!(
            selector.select_all(&table),
            [
                Selection {
                    dst: "2001:db8:1::1".parse()?,
                    src: "2001:db8:1::2".parse()?,
                    src_ifid: IfId::new("en0"),
                },
                Selection {
                    dst: "10.1.2.3".parse::<Ipv4Addr>()?.to_ipv6_mapped(),
                    src: "10.1.2.4".parse::<Ipv4Addr>()?.to_ipv6_mapped(),
                    src_ifid: IfId::new("en0"),
                }
            ]
        );
        Ok(())
    }

    #[test]
    fn dst_addr_selection_matching_scope() -> Result {
        let table = PolicyTable::default();
        let mut selector = AddrSelection::new_with_static(
            vec![
                "2001:db8:1::1".parse()?,
                "198.51.100.121".parse::<Ipv4Addr>()?.to_ipv6_mapped(),
            ],
            vec![
                ("2001:db8:1::2 #en0".parse()?),
                ("fe80::1 #en0".parse()?),
                ("169.254.13.78 #en0".parse()?),
            ],
        );

        assert_eq!(
            selector.select_all(&table),
            [
                Selection {
                    dst: "2001:db8:1::1".parse()?,
                    src: "2001:db8:1::2".parse()?,
                    src_ifid: IfId::new("en0"),
                },
                Selection {
                    dst: "198.51.100.121".parse::<Ipv4Addr>()?.to_ipv6_mapped(),
                    src: "169.254.13.78".parse::<Ipv4Addr>()?.to_ipv6_mapped(),
                    src_ifid: IfId::new("en0"),
                }
            ]
        );

        let mut selector = AddrSelection::new_with_static(
            vec![
                "2001:db8:1::1".parse()?,
                "198.51.100.121".parse::<Ipv4Addr>()?.to_ipv6_mapped(),
            ],
            vec![("fe80::1 #en0".parse()?), ("198.51.100.117 #en0".parse()?)],
        );

        assert_eq!(
            selector.select_all(&table),
            [
                Selection {
                    dst: "198.51.100.121".parse::<Ipv4Addr>()?.to_ipv6_mapped(),
                    src: "198.51.100.117".parse::<Ipv4Addr>()?.to_ipv6_mapped(),
                    src_ifid: IfId::new("en0"),
                },
                Selection {
                    dst: "2001:db8:1::1".parse()?,
                    src: "fe80::1".parse()?,
                    src_ifid: IfId::new("en0"),
                },
            ]
        );
        Ok(())
    }

    #[test]
    fn dst_addr_selection_home_addr() -> Result {
        let table = PolicyTable::default();
        let mut selector = AddrSelection::new_with_static(
            vec!["2001:db8:1::1".parse()?, "fe80::1".parse()?],
            vec![
                ("2001:db8:1::2 #en0 (care-of-addr)".parse()?),
                ("2001:db8:3::1 #en0 (care-of-addr) (home-addr)".parse()?),
                ("fe80::2 #en0 (care-of-addr)".parse()?),
            ],
        );

        assert_eq!(
            selector.select_all(&table),
            [
                Selection {
                    dst: "2001:db8:1::1".parse()?,
                    src: "2001:db8:3::1".parse()?,
                    src_ifid: IfId::new("en0"),
                },
                Selection {
                    dst: "fe80::1".parse()?,
                    src: "fe80::2".parse()?,
                    src_ifid: IfId::new("en0"),
                }
            ]
        );
        Ok(())
    }

    #[test]
    fn dst_addr_select_avoid_depc() -> Result {
        let table = PolicyTable::default();
        let mut selector = AddrSelection::new_with_static(
            vec!["2001:db8:1::1".parse()?, "fe80::1".parse()?],
            vec![
                ("2001:db8:1::2 #en0".parse()?),
                ("fe80::2 #en0 (deprecated)".parse()?),
            ],
        );

        assert_eq!(
            selector.select_all(&table),
            [
                Selection {
                    dst: "2001:db8:1::1".parse()?,
                    src: "2001:db8:1::2".parse()?,
                    src_ifid: IfId::new("en0"),
                },
                Selection {
                    dst: "fe80::1".parse()?,
                    src: "fe80::2".parse()?,
                    src_ifid: IfId::new("en0"),
                }
            ]
        );
        Ok(())
    }
}
