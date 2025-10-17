use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

/// The communication domain of a socket.
#[allow(nonstandard_style)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum SocketDomain {
    AF_UNIX,
    // AF_LOCAL = 0,
    AF_INET,
    AF_AX25,
    AF_IPX,
    AF_APPLETALK,
    AF_X25,
    AF_INET6,
    AF_DECnet,
    AF_KEY,
    AF_NETLINK,
    AF_PACKET,
    AF_RDS,
    AF_PPPOX,
    AF_LLC,
    AF_IB,
    AF_MPLS,
    AF_CAN,
    AF_TIPC,
    AF_BLUETOOTH,
    AF_ALG,
    AF_VSOCK,
    AF_KCM,
    AF_XDP,
}

impl SocketDomain {
    pub const fn addr_unspecified(&self) -> SocketAddr {
        match self {
            Self::AF_INET => SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)),
            Self::AF_INET6 => SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0)),
            Self::AF_UNIX => SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)),
            _ => unreachable!(),
        }
    }
}

/// The type of communications semantics use in the socket.
#[allow(nonstandard_style)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum SocketType {
    SOCK_STREAM,
    SOCK_DGRAM,
    SOCK_SEQPACKET,
    SOCK_RAW,
    SOCK_RDM,
    #[deprecated]
    SOCK_PACKET,
}
