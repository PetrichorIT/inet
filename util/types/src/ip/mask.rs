use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IpMask {
    V4(Ipv4Mask),
    V6(Ipv6Mask),
}

impl IpMask {
    #[must_use]
    pub const fn catch_all_v4() -> Self {
        Self::V4(Ipv4Mask::catch_all())
    }

    #[must_use]
    pub const fn catch_all_v6() -> Self {
        Self::V6(Ipv6Mask::catch_all())
    }

    #[must_use]
    pub fn matches(&self, ip: IpAddr) -> bool {
        match self {
            Self::V4(mask) => {
                let IpAddr::V4(v4) = ip else { return false };
                mask.matches(v4)
            }
            Self::V6(mask) => {
                let IpAddr::V6(v6) = ip else { return false };
                mask.matches(v6)
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ipv4Mask {
    ip: Ipv4Addr,
    mask: Ipv4Addr,
}

impl Ipv4Mask {
    #[must_use]
    pub const fn new(ip: Ipv4Addr, mask: Ipv4Addr) -> Self {
        Self { ip, mask }
    }

    #[must_use]
    pub const fn catch_all() -> Self {
        Self::new(Ipv4Addr::UNSPECIFIED, Ipv4Addr::UNSPECIFIED)
    }

    #[must_use]
    pub fn matches(&self, ip: Ipv4Addr) -> bool {
        let mask = u32::from(self.ip) & u32::from(self.mask);
        let ip = u32::from(ip) & u32::from(self.mask);
        mask == ip
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ipv6Mask {
    ip: Ipv6Addr,
    mask: Ipv6Addr,
}

impl Ipv6Mask {
    #[must_use]
    pub const fn new(ip: Ipv6Addr, mask: Ipv6Addr) -> Self {
        Self { ip, mask }
    }

    #[must_use]
    pub const fn catch_all() -> Self {
        Self::new(Ipv6Addr::UNSPECIFIED, Ipv6Addr::UNSPECIFIED)
    }

    #[must_use]
    pub fn matches(&self, ip: Ipv6Addr) -> bool {
        let mask = u128::from(self.ip) & u128::from(self.mask);
        let ip = u128::from(ip) & u128::from(self.mask);
        mask == ip
    }
}
