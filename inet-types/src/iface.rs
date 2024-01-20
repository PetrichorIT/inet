use bytepack::{BytestreamReader, BytestreamWriter, FromBytestream, ToBytestream};
use des::runtime::random;

use std::{
    fmt::Display,
    io::{Read, Write},
    net::Ipv6Addr,
    ops::{BitAnd, BitOr, BitXor, Not},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MacAddress([u8; 6]);

impl MacAddress {
    pub const NULL: MacAddress = MacAddress([0; 6]);
    pub const BROADCAST: MacAddress = MacAddress([0xff; 6]);

    pub const IPV6_MULTICAST: MacAddress = MacAddress([0x33, 0x33, 0, 0, 0, 0]);
    pub const IPV6_MULTICAST_MASK: MacAddress = MacAddress([0xff, 0xff, 0, 0, 0, 0]);
    pub const PTP_MULTICAST: MacAddress = MacAddress([0x01, 0x1b, 0x19, 0, 0, 0]);
    pub const IPV4_MULTICAST: MacAddress = MacAddress([0x01, 0, 0x5e, 0, 0, 0]);
    pub const IPV4_MULTICAST_MASK: MacAddress = MacAddress([0xff, 0xff, 0xff, 0x80, 0, 0]);

    pub fn ipv6_multicast(ip: Ipv6Addr) -> MacAddress {
        let mut mac = MacAddress::IPV6_MULTICAST;
        mac.0[2..].copy_from_slice(&ip.octets()[12..]);
        mac
    }

    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    #[must_use]
    pub fn gen() -> MacAddress {
        let mut mac = random::<[u8; 6]>();
        mac[0] &= 0b1111_1110;
        MacAddress(mac)
    }

    #[must_use]
    pub fn is_unspecified(&self) -> bool {
        *self == MacAddress::NULL
    }

    #[must_use]
    pub fn is_broadcast(&self) -> bool {
        *self == MacAddress::BROADCAST
    }

    #[must_use]
    pub fn is_multicast(&self) -> bool {
        // TODO: Missing other multicast addrs
        // PTP
        if *self == MacAddress::PTP_MULTICAST {
            return true;
        }
        // Ipv4 multicast
        if *self & MacAddress::IPV4_MULTICAST_MASK == MacAddress::IPV4_MULTICAST {
            return true;
        }
        // Ipv6 multicast
        if *self & MacAddress::IPV6_MULTICAST_MASK == MacAddress::IPV6_MULTICAST {
            return true;
        }
        false
    }

    pub fn embed_into(&self, addr: Ipv6Addr) -> Ipv6Addr {
        let mut bytes = addr.octets();
        bytes[8..11].copy_from_slice(&self.as_slice()[..3]);
        bytes[11] = 0xff;
        bytes[12] = 0xfe;
        bytes[13..].copy_from_slice(&self.as_slice()[3..]);
        Ipv6Addr::from(bytes)
    }
}

impl From<[u8; 6]> for MacAddress {
    fn from(value: [u8; 6]) -> Self {
        MacAddress(value)
    }
}

impl From<MacAddress> for [u8; 6] {
    fn from(value: MacAddress) -> Self {
        value.0
    }
}

macro_rules! bin_ops {
    ($t:ident($f:ident), $v:ident) => {
        impl $t for $v {
            type Output = $v;
            fn $f(mut self, other: Self) -> Self::Output {
                for i in 0..6 {
                    self.0[i] = self.0[i].$f(other.0[i]);
                }
                self
            }
        }
    };
}

bin_ops!(BitOr(bitor), MacAddress);
bin_ops!(BitAnd(bitand), MacAddress);
bin_ops!(BitXor(bitxor), MacAddress);

impl Not for MacAddress {
    type Output = MacAddress;
    fn not(mut self) -> Self::Output {
        for i in 0..6 {
            self.0[i] = self.0[i].not();
        }
        self
    }
}

impl ToBytestream for MacAddress {
    type Error = std::io::Error;
    fn to_bytestream(&self, bytestream: &mut BytestreamWriter) -> Result<(), Self::Error> {
        // BigEndian since as byte array
        bytestream.write_all(&self.0)
    }
}

impl FromBytestream for MacAddress {
    type Error = std::io::Error;
    fn from_bytestream(bytestream: &mut BytestreamReader) -> Result<Self, Self::Error> {
        let mut bytes = [0u8; 6];
        bytestream.read_exact(&mut bytes)?;
        Ok(MacAddress(bytes))
    }
}

impl Display for MacAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv6_embedding() {
        let linklocal = Ipv6Addr::new(0xfe80, 0x1, 0x2, 0x3, 0, 0, 0, 0);
        let mac = MacAddress::from([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        let embedded = mac.embed_into(linklocal);
        assert_eq!(
            embedded,
            Ipv6Addr::new(0xfe80, 0x1, 0x2, 0x3, 0x1122, 0x33ff, 0xfe44, 0x5566)
        );
    }

    #[test]
    fn ipv6_multicast_mac() {
        let dst = Ipv6Addr::new(0x2001, 0xffec, 0x3013, 0, 0, 0, 0x1234, 0x5678);
        let mac = MacAddress::ipv6_multicast(dst);
        assert_eq!(mac, MacAddress([0x33, 0x33, 0x12, 0x34, 0x56, 0x78]));
        assert!(mac.is_multicast());
    }
}
