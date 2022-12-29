/// The flags of an interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[allow(missing_docs)]
pub struct InterfaceFlags {
    pub up: bool,
    pub loopback: bool,
    pub running: bool,
    pub multicast: bool,
    pub p2p: bool,
    pub broadcast: bool,
    pub smart: bool,
    pub simplex: bool,
    pub promisc: bool,
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
        }
    }

    /// The flags for a simple interface
    pub const fn en0() -> Self {
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

        write!(f, ">")
    }
}
