//! Internet-Protocol.

use des::net::message::MessageKind;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

mod mask;
pub use mask::*;

mod v4;
pub use v4::{Ipv4Flags, Ipv4Packet};

mod v6;
pub use v6::{Ipv6AddrExt, Ipv6AddrScope, Ipv6LongestPrefixTable, Ipv6Packet, Ipv6Prefix};

#[cfg(test)]
mod tests;

pub const KIND_IPV4: MessageKind = 0x0800;
pub const KIND_IPV6: MessageKind = 0x86DD;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum IpVersion {
    V4 = 4,
    V6 = 6,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum IpPacket {
    V4(Ipv4Packet),
    V6(Ipv6Packet),
}

#[derive(Debug)]
pub enum IpPacketRef<'a, 'b> {
    V4(&'a Ipv4Packet),
    V6(&'b Ipv6Packet),
}

impl IpPacketRef<'_, '_> {
    #[must_use]
    pub fn tos(&self) -> u8 {
        match self {
            Self::V4(v4) => v4.proto,
            Self::V6(v6) => v6.next_header,
        }
    }

    #[must_use]
    pub fn content(&self) -> &[u8] {
        match self {
            Self::V4(v4) => &v4.content,
            Self::V6(v6) => &v6.content,
        }
    }

    #[must_use]
    pub fn src(&self) -> IpAddr {
        match self {
            Self::V4(v4) => IpAddr::V4(v4.src),
            Self::V6(v6) => IpAddr::V6(v6.src),
        }
    }

    #[must_use]
    pub fn dest(&self) -> IpAddr {
        match self {
            Self::V4(v4) => IpAddr::V4(v4.dst),
            Self::V6(v6) => IpAddr::V6(v6.dst),
        }
    }

    #[must_use]
    pub fn response(&self, content: Vec<u8>) -> IpPacket {
        match self {
            IpPacketRef::V4(pkt) => IpPacket::V4(Ipv4Packet {
                dscp: pkt.dscp,
                enc: pkt.enc,
                identification: pkt.identification,
                flags: pkt.flags,
                fragment_offset: pkt.fragment_offset,
                ttl: 20,
                proto: pkt.proto,
                src: pkt.dst,
                dst: pkt.src,
                content,
            }),
            IpPacketRef::V6(pkt) => IpPacket::V6(Ipv6Packet {
                traffic_class: pkt.traffic_class,
                flow_label: pkt.flow_label,
                next_header: pkt.next_header,
                hop_limit: 20,
                src: pkt.dst,
                dst: pkt.src,
                content,
            }),
        }
    }
}

impl IpPacket {
    #[must_use]
    pub fn version(&self) -> IpVersion {
        if self.is_v4() {
            IpVersion::V4
        } else {
            IpVersion::V6
        }
    }

    #[must_use]
    pub fn tos(&self) -> u8 {
        match self {
            Self::V4(v4) => v4.proto,
            Self::V6(v6) => v6.next_header,
        }
    }

    #[must_use]
    pub fn is_v4(&self) -> bool {
        matches!(self, Self::V4(_))
    }

    #[must_use]
    pub fn is_v6(&self) -> bool {
        matches!(self, Self::V6(_))
    }

    #[must_use]
    pub fn src(&self) -> IpAddr {
        match self {
            Self::V4(pkt) => pkt.src.into(),
            Self::V6(pkt) => pkt.src.into(),
        }
    }

    #[must_use]
    pub fn dst(&self) -> IpAddr {
        match self {
            Self::V4(pkt) => pkt.dst.into(),
            Self::V6(pkt) => pkt.dst.into(),
        }
    }

    pub fn content(&self) -> &[u8] {
        match self {
            Self::V4(v4) => &v4.content,
            Self::V6(v6) => &v6.content,
        }
    }

    #[must_use]
    pub fn new(src: IpAddr, dest: IpAddr, content: Vec<u8>) -> Self {
        use IpAddr::{V4, V6};
        match (src, dest) {
            (V4(src), V4(dest)) => IpPacket::V4(Ipv4Packet {
                dscp: 0,
                enc: 0,
                identification: 0,
                flags: Ipv4Flags {
                    df: false,
                    mf: false,
                },
                fragment_offset: 0,
                ttl: 128,
                proto: 0,
                src,
                dst: dest,
                content,
            }),
            (V6(src), V6(dest)) => IpPacket::V6(Ipv6Packet {
                traffic_class: 0,
                flow_label: 0,
                next_header: 0,
                hop_limit: 128,
                src,
                dst: dest,
                content,
            }),
            _ => unreachable!(),
        }
    }
}

#[must_use]
pub fn ipv4_matches_subnet(ip: Ipv4Addr, subnet: Ipv4Addr, mask: Ipv4Addr) -> bool {
    let ip = ip.octets();
    let subnet = subnet.octets();
    let mask = mask.octets();

    mask[0] & ip[0] == mask[0] & subnet[0]
        && mask[1] & ip[1] == mask[1] & subnet[1]
        && mask[2] & ip[2] == mask[2] & subnet[2]
        && mask[3] & ip[3] == mask[3] & subnet[3]
}

#[must_use]
pub fn ipv6_matches_subnet(ip: Ipv6Addr, subnet: Ipv6Addr, mask: Ipv6Addr) -> bool {
    let ip = ip.octets();
    let subnet = subnet.octets();
    let mask = mask.octets();

    for i in 0..16 {
        if ip[i] & mask[i] != subnet[i] & mask[i] {
            return false;
        }
    }

    true
}

pub fn ipv6_matches_subnet_len(ip: Ipv6Addr, subnet: Ipv6Addr, prefix_len: u8) -> bool {
    let ip_u128 = u128::from(ip);
    let subnet_u128 = u128::from(subnet);
    let mask_u128 = u128::MAX << (128 - prefix_len);
    ip_u128 & mask_u128 == subnet_u128 & mask_u128
}
