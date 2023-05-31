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
