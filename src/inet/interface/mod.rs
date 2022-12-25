use crate::ip::{IPPacket, IPVersion, KIND_IP};
use std::fmt::{self, Display};
use std::net::Ipv4Addr;

mod flags;
use des::prelude::{GateRef, Message};
pub use flags::InterfaceFlags;

mod addrs;
pub use addrs::InterfaceAddr;

mod device;
pub use device::NetworkDevice;

use super::IOContext;

macro_rules! hash {
    ($v:expr) => {{
        use std::hash::Hash;
        use std::hash::Hasher;

        let mut s = ::std::collections::hash_map::DefaultHasher::new();
        ($v).hash(&mut s);
        s.finish()
    }};
}

// # Interface

/// A network interface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Interface {
    /// The name of the interface
    pub name: InterfaceName,
    /// The device
    pub device: NetworkDevice,
    /// The flags.
    pub flags: InterfaceFlags,
    /// The associated addrs.
    pub addrs: Vec<InterfaceAddr>,
    /// The status
    pub status: InterfaceStatus,
    /// The device
    pub(crate) prio: usize,
}

impl Interface {
    /// Creates a loopback interface
    pub fn loopback() -> Self {
        Self {
            name: "lo0".into(),
            device: NetworkDevice::LoopbackDevice,
            flags: InterfaceFlags::loopback(),
            addrs: Vec::from(InterfaceAddr::loopback()),
            status: InterfaceStatus::Active,
            prio: 100,
        }
    }

    /// Creates a loopback interface
    pub fn en0(ether: [u8; 6], v4: Ipv4Addr, device: NetworkDevice) -> Self {
        Self {
            name: "en0".into(),
            device,
            flags: InterfaceFlags::en0(),
            addrs: Vec::from(InterfaceAddr::en0(ether, v4)),
            status: InterfaceStatus::Active,
            prio: 10,
        }
    }

    pub(crate) fn send_ip(&self, mut ip: IPPacket) {
        assert!(
            self.status == InterfaceStatus::Active,
            "Cannot send on inactive context"
        );

        let addr = self
            .get_interface_addr_v4()
            .expect("Failed to fetch interface v4 addr");
        ip.src = addr;
        ip.version = IPVersion::V4;

        let msg = Message::new().kind(KIND_IP).content(ip).build();
        self.send_mtu(msg)
    }

    pub(crate) fn get_interface_addr_v4(&self) -> Option<Ipv4Addr> {
        for addr in &self.addrs {
            if let InterfaceAddr::Inet { addr, .. } = addr {
                return Some(*addr);
            }
        }
        None
    }

    pub(crate) fn send_mtu(&self, mtu: Message) {
        self.device.send_mtu(mtu)
    }

    pub(super) fn last_gate_matches(&self, last_gate: &Option<GateRef>) -> bool {
        self.device.last_gate_matches(last_gate)
    }
}

// # Interface Name

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct InterfaceName {
    pub(super) name: String,
    pub(super) hash: u64,
    pub(super) parent: Option<Box<InterfaceName>>,
}

impl InterfaceName {
    pub fn new(s: impl AsRef<str>) -> Self {
        let name = s.as_ref().to_string();
        let hash = hash!(name);
        Self {
            name,
            hash,
            parent: None,
        }
    }
}

impl Display for InterfaceName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(parent) = self.parent.as_ref() {
            write!(f, "{}:{}", parent, self.name)
        } else {
            self.name.fmt(f)
        }
    }
}

impl<T: AsRef<str>> From<T> for InterfaceName {
    fn from(value: T) -> Self {
        Self::new(value)
    }
}

// # Interface Status

/// The status of a network interface
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum InterfaceStatus {
    /// The interface is active and can be used.
    Active,
    /// The interface is only pre-configures not really there.
    #[default]
    Inactive,
}

impl fmt::Display for InterfaceStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            Self::Active => write!(f, "active"),
            Self::Inactive => write!(f, "inactive"),
        }
    }
}

impl IOContext {}
