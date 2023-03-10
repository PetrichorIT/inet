//! Internet-Protocol.

use des::net::message::MessageKind;
use std::net::{IpAddr, Ipv4Addr};

mod mask;
pub use mask::*;

mod v4;
pub use v4::{Ipv4Flags, Ipv4Packet};

mod v6;
pub use v6::Ipv6Packet;

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
pub(crate) enum IpPacketRef<'a, 'b> {
    V4(&'a Ipv4Packet),
    V6(&'b Ipv6Packet),
}

impl IpPacketRef<'_, '_> {
    pub(crate) fn tos(&self) -> u8 {
        match self {
            Self::V4(v4) => v4.proto,
            Self::V6(v6) => v6.next_header,
        }
    }

    pub(crate) fn content(&self) -> &Vec<u8> {
        match self {
            Self::V4(v4) => &v4.content,
            Self::V6(v6) => &v6.content,
        }
    }

    pub(crate) fn src(&self) -> IpAddr {
        match self {
            Self::V4(v4) => IpAddr::V4(v4.src),
            Self::V6(v6) => IpAddr::V6(v6.src),
        }
    }

    pub(crate) fn dest(&self) -> IpAddr {
        match self {
            Self::V4(v4) => IpAddr::V4(v4.dest),
            Self::V6(v6) => IpAddr::V6(v6.dest),
        }
    }
}

impl IpPacket {
    pub fn version(&self) -> IpVersion {
        if self.is_v4() {
            IpVersion::V4
        } else {
            IpVersion::V6
        }
    }

    pub(crate) fn kind(&self) -> MessageKind {
        if self.is_v4() {
            KIND_IPV4
        } else {
            KIND_IPV6
        }
    }

    pub(crate) fn set_src(&mut self, src: IpAddr) {
        match (self, src) {
            (Self::V4(v4), IpAddr::V4(addr)) => v4.src = addr,
            (Self::V6(v6), IpAddr::V6(addr)) => v6.src = addr,
            _ => unreachable!(),
        }
    }

    pub fn is_v4(&self) -> bool {
        matches!(self, Self::V4(_))
    }

    pub fn is_v6(&self) -> bool {
        matches!(self, Self::V6(_))
    }

    pub(crate) fn dest(&self) -> IpAddr {
        match self {
            Self::V4(v4) => IpAddr::V4(v4.dest),
            Self::V6(v6) => IpAddr::V6(v6.dest),
        }
    }
}

pub(crate) fn ipv4_matches_subnet(ip: Ipv4Addr, subnet: Ipv4Addr, mask: Ipv4Addr) -> bool {
    let ip = ip.octets();
    let subnet = subnet.octets();
    let mask = mask.octets();

    mask[0] & ip[0] == mask[0] & subnet[0]
        && mask[1] & ip[1] == mask[1] & subnet[1]
        && mask[2] & ip[2] == mask[2] & subnet[2]
        && mask[3] & ip[3] == mask[3] & subnet[3]
}
