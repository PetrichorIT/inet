use std::{
    error, fmt,
    net::{AddrParseError, Ipv6Addr},
    num::ParseIntError,
    str::FromStr,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
#[repr(u8)]
pub enum Ipv6AddrScope {
    InterfaceLocal = 0,
    UnicastLinkLocal = 1,
    MulticastLinkLocal = 2,
    RealmLocal = 3,
    AdminLocal = 4,
    SiteLocal = 5,
    OrganizationLocal = 6,
    UnicastGlobal,
    MulticastGlobal = 8,
}

impl Ipv6AddrScope {
    pub fn new(addr: Ipv6Addr) -> Self {
        if addr.is_multicast() {
            match addr.segments()[0] & 0x000f {
                1 => Self::InterfaceLocal,
                2 => Self::MulticastLinkLocal,
                3 => Self::RealmLocal,
                4 => Self::AdminLocal,
                5 => Self::SiteLocal,
                8 => Self::OrganizationLocal,
                14 => Self::MulticastGlobal,
                scope => panic!("Unknown multicast address {addr}: unknown scope {scope}"),
            }
        } else {
            if let Some(ipv4) = addr.to_ipv4_mapped() {
                if ipv4.octets()[0] == 169 && ipv4.octets()[1] == 254 {
                    return Self::UnicastLinkLocal;
                }
                if ipv4.octets()[0] == 127 {
                    return Self::UnicastLinkLocal;
                }

                Self::UnicastGlobal
            } else {
                if (addr.segments()[0] & 0xffc0) == 0xfe80 {
                    // LinkLocal addr
                    return Self::UnicastLinkLocal;
                }
                if addr == Ipv6Addr::LOCALHOST {
                    return Self::UnicastLinkLocal;
                }

                if addr.to_ipv4().is_some() {
                    // other ipv4 addr
                    return Self::UnicastGlobal;
                }

                Self::UnicastGlobal
            }
        }
    }

    fn as_ord_idx(&self) -> u8 {
        *self as u8
    }
}

impl PartialOrd for Ipv6AddrScope {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Ipv6AddrScope {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.as_ord_idx().cmp(&other.as_ord_idx())
    }
}
pub trait Ipv6AddrExt {
    const LINK_LOCAL: Ipv6Addr = Ipv6Prefix::LINK_LOCAL.addr();
    const MULTICAST_ALL_NODES: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);
    const MULTICAST_ALL_ROUTERS: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 2);
    const ONES: Ipv6Addr = Ipv6Addr::new(
        0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff,
    );

    fn solicied_node_multicast(addr: Ipv6Addr) -> Self;

    fn is_link_local(&self) -> bool;

    fn scope(&self) -> Ipv6AddrScope;
}

impl Ipv6AddrExt for Ipv6Addr {
    fn solicied_node_multicast(addr: Ipv6Addr) -> Self {
        let mut bytes = [0; 16];
        bytes[0] = 0xff;
        bytes[1] = 0x02;
        // pad
        bytes[11] = 0x01;
        bytes[12] = 0xff;
        bytes[13..].copy_from_slice(&mut addr.octets()[13..]);
        Ipv6Addr::from(bytes)
    }

    fn is_link_local(&self) -> bool {
        Ipv6Prefix::LINK_LOCAL.contains(*self)
    }

    fn scope(&self) -> Ipv6AddrScope {
        Ipv6AddrScope::new(*self)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ipv6Prefix {
    addr: Ipv6Addr,
    len: u8,
}

impl Ipv6Prefix {
    pub const LINK_LOCAL: Ipv6Prefix =
        Ipv6Prefix::new_unchcecked(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0), 64);

    pub fn new(prefix: Ipv6Addr, len: u8) -> Self {
        assert!(len <= 128);
        let prefix = if len == 0 {
            Ipv6Addr::UNSPECIFIED
        } else {
            let mask = Ipv6Addr::from(u128::MAX << (128 - len));
            prefix & mask
        };
        Self::new_unchcecked(prefix, len)
    }

    pub fn fit(addr: Ipv6Addr) -> Self {
        let len = 128 - u128::from(addr).trailing_zeros();
        Self::new(addr, len as u8)
    }

    #[inline]
    const fn new_unchcecked(prefix: Ipv6Addr, len: u8) -> Self {
        Self { addr: prefix, len }
    }

    pub const fn addr(&self) -> Ipv6Addr {
        self.addr
    }

    pub const fn len(&self) -> u8 {
        self.len
    }

    #[inline(always)]
    fn mask(&self) -> u128 {
        if self.len == 0 {
            0
        } else {
            u128::MAX << (128 - self.len)
        }
    }

    pub fn contains(&self, addr: Ipv6Addr) -> bool {
        let addr = u128::from(addr);
        let prefix = u128::from(self.addr);
        let mask = self.mask();
        addr & mask == prefix
    }

    pub fn common_prefix_len(&self, other: Ipv6Addr) -> usize {
        let s = u128::from(self.addr);
        let d = u128::from(other);
        let xored = s ^ d;
        (xored.leading_zeros() as usize).min(self.len as usize)
    }
}

impl PartialEq<(Ipv6Addr, u8)> for Ipv6Prefix {
    fn eq(&self, other: &(Ipv6Addr, u8)) -> bool {
        self.addr == other.0 && self.len == other.1
    }
}

impl fmt::Debug for Ipv6Prefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.len)
    }
}

impl fmt::Display for Ipv6Prefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.len)
    }
}

impl FromStr for Ipv6Prefix {
    type Err = Ipv6PrefixParsingError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let split = s.split('/').collect::<Vec<_>>();
        if split.len() != 2 {
            return Err(Ipv6PrefixParsingError::MissingPrefixLen);
        }
        let prefix = split[0]
            .parse()
            .map_err(|e| Ipv6PrefixParsingError::AddrParseError(e))?;
        let len = split[1]
            .parse()
            .map_err(|e| Ipv6PrefixParsingError::ParseIntError(e))?;
        Ok(Self::new(prefix, len))
    }
}

pub struct Ipv6LongestPrefixTable<E> {
    inner: Vec<(Ipv6Prefix, E)>,
}

impl<E> Ipv6LongestPrefixTable<E> {
    pub fn new() -> Self {
        Self { inner: Vec::new() }
    }

    pub fn insert(&mut self, prefix: Ipv6Prefix, entry: E) {
        match self
            .inner
            .binary_search_by(|v| prefix.len().cmp(&v.0.len()))
        {
            Ok(i) | Err(i) => self.inner.insert(i, (prefix, entry)),
        }
    }

    pub fn remove(&mut self, prefix: Ipv6Prefix) {
        self.inner.retain(|(key, _)| *key == prefix)
    }

    pub fn lookup(&self, addr: Ipv6Addr) -> Option<&E> {
        self.inner.iter().find_map(|(prefix, entry)| {
            if prefix.contains(addr) {
                Some(entry)
            } else {
                None
            }
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ipv6PrefixParsingError {
    MissingPrefixLen,
    AddrParseError(AddrParseError),
    ParseIntError(ParseIntError),
}

impl fmt::Display for Ipv6PrefixParsingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl error::Error for Ipv6PrefixParsingError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unicast_local_scope() {
        let addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0);
        assert_eq!(addr.scope(), Ipv6AddrScope::UnicastLinkLocal);

        let addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0xff, 0xffff, 0xffff, 0xffff);
        assert_eq!(addr.scope(), Ipv6AddrScope::UnicastLinkLocal);

        let addr = Ipv6Addr::LOCALHOST;
        assert_eq!(addr.scope(), Ipv6AddrScope::UnicastLinkLocal);

        // non routable
        let addr = Ipv6Addr::new(0xfe80, 1, 0, 0, 0, 0, 0, 0);
        assert!(!addr.is_link_local());
        assert_eq!(addr.scope(), Ipv6AddrScope::UnicastLinkLocal);
    }

    #[test]
    fn unicast_global_scope() {
        let addr = Ipv6Addr::new(0x2002, 0, 0, 1, 2, 3, 4, 5);
        assert_eq!(addr.scope(), Ipv6AddrScope::UnicastGlobal);

        let addr = Ipv6Addr::new(
            0x2001, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff,
        );
        assert_eq!(addr.scope(), Ipv6AddrScope::UnicastGlobal);

        let addr = Ipv6Addr::new(
            0x1928, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff,
        );
        assert_eq!(addr.scope(), Ipv6AddrScope::UnicastGlobal);
    }

    #[test]
    fn multicast_scopes() {
        let addr = Ipv6Addr::new(0xff01, 0, 1, 2, 3, 4, 5, 6);
        assert_eq!(addr.scope(), Ipv6AddrScope::InterfaceLocal);

        let addr = Ipv6Addr::new(0xff02, 0, 1, 2, 3, 4, 5, 6);
        assert_eq!(addr.scope(), Ipv6AddrScope::MulticastLinkLocal);

        let addr = Ipv6Addr::new(0xff04, 0, 1, 2, 3, 4, 5, 6);
        assert_eq!(addr.scope(), Ipv6AddrScope::AdminLocal);

        let addr = Ipv6Addr::new(0xff05, 0, 1, 2, 3, 4, 5, 6);
        assert_eq!(addr.scope(), Ipv6AddrScope::SiteLocal);

        let addr = Ipv6Addr::new(0xff08, 0, 1, 2, 3, 4, 5, 6);
        assert_eq!(addr.scope(), Ipv6AddrScope::OrganizationLocal);

        let addr = Ipv6Addr::new(0xff0e, 0, 1, 2, 3, 4, 5, 6);
        assert_eq!(addr.scope(), Ipv6AddrScope::MulticastGlobal);
    }

    #[test]
    fn common_prefix_len() {
        assert_eq!(
            Ipv6Prefix::LINK_LOCAL.common_prefix_len(Ipv6Addr::new(0xfe80, 0, 0, 0, 12, 3, 4, 1)),
            64
        );

        assert_eq!(
            Ipv6Prefix::LINK_LOCAL
                .common_prefix_len(Ipv6Addr::new(0xfe80, 0, 0xffff, 0, 12, 3, 4, 1)),
            32
        );
    }

    #[test]
    fn longest_prefix_table_insert() {
        let mut tbl = Ipv6LongestPrefixTable::new();
        tbl.insert(
            Ipv6Prefix {
                addr: Ipv6Addr::UNSPECIFIED,
                len: 64,
            },
            1,
        );
        tbl.insert(
            Ipv6Prefix {
                addr: Ipv6Addr::UNSPECIFIED,
                len: 32,
            },
            2,
        );
        tbl.insert(
            Ipv6Prefix {
                addr: Ipv6Addr::UNSPECIFIED,
                len: 69,
            },
            3,
        );

        assert_eq!(tbl.inner.iter().map(|v| v.1).collect::<Vec<_>>(), [3, 1, 2])
    }
}
