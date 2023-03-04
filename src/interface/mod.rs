//! Network interfaces and devices.

use super::IOContext;
use crate::{
    bsd::Fd,
    ip::{IpPacket, IpVersion},
};
use des::prelude::{
    module_id, schedule_at, schedule_in, GateRef, Message, MessageBody, MessageKind, SimTime,
};
use std::{
    fmt::{self, Display},
    io::{Error, ErrorKind, Result},
    net::{IpAddr, Ipv4Addr},
    time::Duration,
};

mod flags;
pub use flags::InterfaceFlags;

mod addrs;
pub use addrs::InterfaceAddr;

mod device;
pub use device::NetworkDevice;

mod api;
pub use api::*;

macro_rules! hash {
    ($v:expr) => {{
        use std::hash::Hash;
        use std::hash::Hasher;
        let mut s = ::std::collections::hash_map::DefaultHasher::new();
        ($v).hash(&mut s);
        s.finish()
    }};
}

/// Interface identifier.
#[derive(Clone, Copy, PartialEq, Eq, Hash, MessageBody)]
#[repr(transparent)]
pub struct IfId(u64);

impl IfId {
    pub(crate) const fn null() -> IfId {
        IfId(0)
    }
}

impl fmt::Debug for IfId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        <Self as Display>::fmt(self, f)
    }
}
impl Display for IfId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:x}", self.0)
    }
}

// # Interface

pub(super) const KIND_LINK_UNBUSY: MessageKind = 0x0500;

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
    /// State
    pub state: InterfaceBusyState,

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
            state: InterfaceBusyState::Idle,
        }
    }

    pub fn ethernet(ip_addrs: &[IpAddr], device: NetworkDevice) -> Self {
        let mut addrs = Vec::new();
        let id = module_id().0.to_be_bytes();
        addrs.push(InterfaceAddr::Ether {
            addr: [0xff, 0, 0, 0, id[1], id[0]],
        });
        for addr in ip_addrs {
            match addr {
                IpAddr::V4(v4) => {
                    addrs.push(InterfaceAddr::Inet {
                        addr: *v4,
                        netmask: Ipv4Addr::new(255, 255, 255, 0),
                    });
                    addrs.push(InterfaceAddr::Inet6 {
                        addr: v4.to_ipv6_mapped(),
                        prefixlen: 128,
                        scope_id: None,
                    });
                }
                IpAddr::V6(v6) => {
                    addrs.push(InterfaceAddr::Inet6 {
                        addr: *v6,
                        prefixlen: 128,
                        scope_id: None,
                    });
                    if let Some(v4) = v6.to_ipv4_mapped() {
                        addrs.push(InterfaceAddr::Inet {
                            addr: v4,
                            netmask: Ipv4Addr::new(255, 255, 255, 0),
                        });
                    }
                }
            }
        }

        Self {
            name: "en0".into(),
            device,
            flags: InterfaceFlags::en0(),
            addrs,
            status: InterfaceStatus::Active,
            prio: 5,
            state: InterfaceBusyState::Idle,
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
            state: InterfaceBusyState::Idle,
        }
    }

    pub(crate) fn send_ip(&mut self, mut ip: IpPacket) -> Result<()> {
        assert!(
            self.status == InterfaceStatus::Active,
            "Cannot send on inactive context"
        );

        let version = ip.version();

        let addr = self
            .get_interface_addr_for(version)
            .expect("Failed to fetch interface addr");
        ip.set_src(addr);

        let target_loopback = ip.dest().is_loopback();

        let mut msg = Message::new().kind(ip.kind());
        match ip {
            IpPacket::V4(v4) => msg = msg.content(v4),
            IpPacket::V6(v6) => msg = msg.content(v6),
        }

        if target_loopback {
            schedule_in(msg.build(), Duration::ZERO);
            Ok(())
        } else {
            self.send(msg.build())
        }
    }

    pub(crate) fn get_interface_addr_for(&self, version: IpVersion) -> Option<IpAddr> {
        for addr in &self.addrs {
            match (addr, version) {
                (InterfaceAddr::Inet { addr, .. }, IpVersion::V4) => {
                    return Some(IpAddr::V4(*addr))
                }
                (InterfaceAddr::Inet6 { addr, .. }, IpVersion::V6) => {
                    return Some(IpAddr::V6(*addr))
                }
                _ => {}
            }
        }
        None
    }

    pub(crate) fn send(&mut self, message: Message) -> Result<()> {
        if self.state != InterfaceBusyState::Idle {
            return Err(Error::new(
                ErrorKind::WouldBlock,
                "interface is busy - would block",
            ));
        }

        self.state = self.device.send(message);
        if let InterfaceBusyState::Busy { until, .. } = &self.state {
            schedule_at(
                Message::new()
                    .kind(KIND_LINK_UNBUSY)
                    .content(self.name.id)
                    .build(),
                *until,
            );
        }

        Ok(())
    }

    pub(super) fn link_update(&mut self) -> Vec<Fd> {
        assert!(!self.device.is_busy(), "Link notif send invalid message");
        let mut swap = InterfaceBusyState::Idle;
        std::mem::swap(&mut swap, &mut self.state);

        let InterfaceBusyState::Busy { interests, .. } = swap else {
            panic!("Huh failure")
        };
        interests
    }

    pub(super) fn last_gate_matches(&self, last_gate: &Option<GateRef>) -> bool {
        self.device.last_gate_matches(last_gate)
    }

    pub(super) fn add_write_interest(&mut self, fd: Fd) {
        if let InterfaceBusyState::Busy { interests, .. } = &mut self.state {
            interests.push(fd);
        }
    }

    pub fn is_busy(&self) -> bool {
        matches!(self.state, InterfaceBusyState::Busy { .. })
    }
}

// # Interface Name

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct InterfaceName {
    pub(super) name: String,
    pub(super) id: IfId,
    pub(super) parent: Option<Box<InterfaceName>>,
}

impl InterfaceName {
    pub fn new(s: impl AsRef<str>) -> Self {
        let name = s.as_ref().to_string();
        let hash = hash!(name);
        Self {
            name,
            id: IfId(hash),
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
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> std::result::Result<(), fmt::Error> {
        match self {
            Self::Active => write!(f, "active"),
            Self::Inactive => write!(f, "inactive"),
        }
    }
}

// # Busy state

/// The state of the interface
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum InterfaceBusyState {
    Idle,
    Busy { until: SimTime, interests: Vec<Fd> },
}

// # IOContext

impl IOContext {
    pub(super) fn add_interface(&mut self, iface: Interface) {
        if self.interfaces.get(&iface.name.id).is_some() {
            unimplemented!()
        } else {
            self.interfaces.insert(iface.name.id, iface);
        }
    }

    pub(super) fn get_interfaces(&self) -> Vec<Interface> {
        self.interfaces.values().cloned().collect::<Vec<_>>()
    }

    pub(super) fn capture_link_update(&mut self, msg: Message) -> Option<Message> {
        let Some(ifid) = msg.try_content::<IfId>() else {
            return Some(msg)
        };

        let Some(interface) = self.interfaces.get_mut(ifid) else {
            return Some(msg)
        };

        let updates = interface.link_update();
        for socket in updates {
            self.bsd_socket_link_update(socket, *ifid);
        }
        None
    }

    pub(super) fn get_interface_for_ip_packet(
        &self,
        dest: IpAddr,
        last_gate: Option<GateRef>,
    ) -> Vec<IfId> {
        let mut ifaces = self
            .interfaces
            .iter()
            .filter(|(_, iface)| iface.status == InterfaceStatus::Active && iface.flags.up)
            .filter(|(_, iface)| iface.last_gate_matches(&last_gate))
            .filter(|(_, iface)| iface.addrs.iter().any(|addr| addr.matches_ip(dest)))
            .collect::<Vec<_>>();

        ifaces.sort_by(|(_, l), (_, r)| r.prio.cmp(&l.prio));

        ifaces.into_iter().map(|v| *v.0).collect::<Vec<_>>()
    }
}
