use std::fmt::Display;

use serde::{Deserialize, Serialize};
use valuable::Valuable;

/// Flags indicating the state and capabilities of a network interface
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Valuable)]
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

impl Display for InterfaceFlags {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        const FMT_STMT: [&str; 11] = [
            "UP",
            "LOOPBACK",
            "RUNNING",
            "MULTICAST",
            "POINTTOPOINT",
            "BROADCAST",
            "SMART",
            "SIMPLEX",
            "PROMISC",
            "ROUTER",
            "V6",
        ];

        let flags = [
            self.up,
            self.loopback,
            self.running,
            self.multicast,
            self.p2p,
            self.broadcast,
            self.smart,
            self.simplex,
            self.promisc,
            self.router,
            self.v6,
        ];

        write!(f, "flags=< ")?;
        for (_, flag) in flags.iter().zip(FMT_STMT).filter(|(enabled, _)| **enabled) {
            write!(f, "{flag} ")?;
        }
        write!(f, ">")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fmt() {
        let flags = InterfaceFlags::en0(true);
        assert_eq!(
            flags.to_string(),
            "flags=< UP RUNNING MULTICAST BROADCAST SMART SIMPLEX V6 >"
        );
    }
}
