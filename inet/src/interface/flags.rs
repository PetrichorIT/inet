/// Flags indicating the state and capabilities of a network interface
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[allow(missing_docs)]
pub struct InterfaceFlags {
    /// Whether the interface is connected
    pub up: bool,
    /// Whether the interface should be used as the loopback interface
    pub loopback: bool,
    /// Whether active protocol components  of L2 protocols are allowed
    pub running: bool,
    /// Whether the interface supports multicast
    pub multicast: bool,
    /// Wether the interface exclusivly allows point-to-point traffic
    pub p2p: bool,
    /// Wether the interface supports link layer broadcasting
    pub broadcast: bool,
    /// *Not currently in use*
    pub smart: bool,
    /// *Not currently in use*
    pub simplex: bool,
    /// *Not currently in use*
    pub promisc: bool,
    /// Whether the node is a router,
    pub router: bool,
    /// Wether this interface shoulc be Ipv6 configured
    pub v6: bool,
}

impl InterfaceFlags {
    /// The flags for the loopback interface
    pub const fn loopback() -> Self {
        Self {
            up: true,
            loopback: true,
            running: true,
            multicast: true,
            p2p: false,
            broadcast: false,
            smart: false,
            simplex: false,
            promisc: false,
            router: false,
            v6: true,
        }
    }

    /// The flags for a simple interface
    pub const fn en0(v6: bool) -> Self {
        Self {
            up: true,
            loopback: false,
            running: true,
            multicast: true,
            p2p: false,
            broadcast: true,
            smart: true,
            simplex: true,
            promisc: false,
            router: false,
            v6,
        }
    }
}

impl std::fmt::Display for InterfaceFlags {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(f, "flags=<")?;
        if self.up {
            write!(f, "UP")?
        }
        if self.loopback {
            write!(f, "LOOPBACK")?
        }
        if self.running {
            write!(f, "RUNNING")?
        }
        if self.multicast {
            write!(f, "MULTICAST")?
        }
        if self.p2p {
            write!(f, "POINTTOPOINT")?
        }
        if self.broadcast {
            write!(f, "BROADCAST")?
        }
        if self.smart {
            write!(f, "SMART")?
        }
        if self.simplex {
            write!(f, "SIMPLEX")?
        }
        if self.promisc {
            write!(f, "PROMISC")?
        }
        if self.router {
            write!(f, "ROUTER")?
        }

        write!(f, ">")
    }
}
