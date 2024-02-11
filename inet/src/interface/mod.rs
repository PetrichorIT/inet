//! Network interfaces and Network devices.
//!
//!

use std::{
    collections::VecDeque,
    io::{self, Error, ErrorKind, Result},
};

use crate::socket::Fd;
use crate::IOContext;
use des::prelude::*;
use inet_types::arp::KIND_ARP;
use inet_types::iface::MacAddress;
use inet_types::{arp::ArpPacket, ip::Ipv6AddrExt};

macro_rules! hash {
    ($v:expr) => {{
        use std::hash::Hash;
        use std::hash::Hasher;
        let mut s = ::std::collections::hash_map::DefaultHasher::new();
        ($v).hash(&mut s);
        s.finish()
    }};
}

mod api;
pub use self::api::*;

mod device;
pub use self::device::*;

mod types;
pub use self::types::*;

mod flags;
pub use flags::*;

mod addrs;
pub use self::addrs::*;

/// A network interface, mapping a physical network device
/// to internal abstractions
#[derive(Debug)]
pub struct Interface {
    /// The name of the interface.
    ///
    /// A name uniquely identifies an interface, either directly or through the
    /// interface-id derived from the name. No two interfaces on the same node
    /// should share either name or id.
    pub name: InterfaceName,
    /// The physical network device, representing a NIC in most cases.
    ///
    /// This device will be used on receive / send packets using this inteface. In OSI
    /// terms, this represents the physical layer device.
    pub device: NetworkDevice,
    /// Flags indicating the state and capabilities of the associated device.
    pub flags: InterfaceFlags,
    /// A list of addresses bound to this interface.
    pub addrs: InterfaceAddrs,
    /// The internal state of the interface
    pub status: InterfaceStatus,
    /// A flag indicating whether the interface is currently busy sending
    pub state: InterfaceBusyState,

    pub(crate) prio: usize,
    pub(crate) buffer: VecDeque<Message>,
}

/// A result forwarded after linklayer processing
#[derive(Debug)]
pub enum LinkLayerResult {
    /// The packet does not attach to any link layer interface, so its custom made.
    /// Pass it through the entires IOPlugin
    PassThrough(Message),
    /// The packet was consumed by the link layer thus neeeds no futher
    /// processing,
    Consumed(),
    /// The packet was received on the given interface and should be
    /// passed through to the network layer.
    NetworkingPacket(Message, IfId),
    /// An IO timeout for the networking layer.
    Timeout(Message),
}

impl Interface {
    pub fn empty(name: &str, device: NetworkDevice) -> Self {
        Self {
            name: InterfaceName::new(name),
            device,
            flags: InterfaceFlags::en0(true),
            addrs: InterfaceAddrs::new(Vec::new()),
            status: InterfaceStatus::Active,
            state: InterfaceBusyState::Idle,
            prio: 0,
            buffer: VecDeque::new(),
        }
    }

    pub fn ethv6_autocfg(device: NetworkDevice) -> Self {
        let link_local = InterfaceAddr::ipv6_link_local(device.addr);
        Self {
            name: InterfaceName::new("en0"),
            device,
            flags: InterfaceFlags::en0(true),
            addrs: InterfaceAddrs::new(vec![link_local]),
            status: InterfaceStatus::Active,
            state: InterfaceBusyState::Idle,
            prio: 200,
            buffer: VecDeque::new(),
        }
    }

    /// Creates a new ethernet interface using the given device
    /// and an IP address for binding to a LAN.
    pub fn eth(device: NetworkDevice, ip: IpAddr) -> Interface {
        match ip {
            IpAddr::V4(v4) => Self::ethv4(device, v4),
            IpAddr::V6(v6) => Self::ethv6(device, v6),
        }
    }

    /// Creates a new ethernet interface bound to an Ipv4/24 network.
    pub fn ethv4(device: NetworkDevice, v4: Ipv4Addr) -> Interface {
        Self::ethv4_named("en0", device, v4, Ipv4Addr::new(255, 255, 255, 0))
    }

    /// Creates a new ethernet interface bound to an Ipv6/64 network.
    pub fn ethv6(device: NetworkDevice, v6: Ipv6Addr) -> Interface {
        Self::ethv6_named("en1", device, v6)
    }

    /// Creates a new ethernet interface using the provided parameters.
    pub fn ethv4_named(
        name: impl AsRef<str>,
        device: NetworkDevice,
        subnet: Ipv4Addr,
        mask: Ipv4Addr,
    ) -> Interface {
        Interface {
            name: InterfaceName::new(name),
            device,
            flags: InterfaceFlags::en0(false),
            addrs: InterfaceAddrs::new(vec![InterfaceAddr::Inet {
                addr: subnet,
                netmask: mask,
            }]),
            status: InterfaceStatus::Active,
            state: InterfaceBusyState::Idle,
            prio: 100,
            buffer: VecDeque::new(),
        }
    }

    pub fn ethv6_named_linklocal(name: impl AsRef<str>, device: NetworkDevice) -> Interface {
        let addr = device.addr.embed_into(Ipv6Addr::LINK_LOCAL);
        Self::ethv6_named(name, device, addr)
    }

    pub fn eth_empty(name: impl AsRef<str>, device: NetworkDevice) -> Interface {
        Interface {
            name: InterfaceName::new(name),
            device,
            flags: InterfaceFlags::en0(false),
            addrs: InterfaceAddrs::new(Vec::new()),
            status: InterfaceStatus::Active,
            state: InterfaceBusyState::Idle,
            prio: 200,
            buffer: VecDeque::new(),
        }
    }

    /// Creates a new ethernet interface using the provided parameters.
    pub fn ethv6_named(
        name: impl AsRef<str>,
        device: NetworkDevice,
        subnet: Ipv6Addr,
    ) -> Interface {
        assert!(
            !subnet.is_multicast() && !subnet.is_unspecified(),
            "requires unicast address for interface definition"
        );
        Interface {
            name: InterfaceName::new(name),
            device,
            flags: InterfaceFlags::en0(true),
            addrs: InterfaceAddrs::new(vec![InterfaceAddr::Inet6(InterfaceAddrV6::new_static(
                subnet, 64,
            ))]),
            status: InterfaceStatus::Active,
            state: InterfaceBusyState::Idle,
            prio: 200,
            buffer: VecDeque::new(),
        }
    }

    /// Creates a new ethernet interface using the provided parameters.
    pub fn eth_mixed(
        name: impl AsRef<str>,
        device: NetworkDevice,
        v4: (Ipv4Addr, Ipv4Addr),
        v6: (Ipv6Addr, usize),
    ) -> Interface {
        Interface {
            name: InterfaceName::new(name),
            device,
            flags: InterfaceFlags::en0(true),
            addrs: InterfaceAddrs::new(vec![
                InterfaceAddr::Inet {
                    addr: v4.0,
                    netmask: v4.1,
                },
                InterfaceAddr::Inet6(InterfaceAddrV6::new_static(v6.0, v6.1)),
            ]),
            status: InterfaceStatus::Active,
            state: InterfaceBusyState::Idle,
            prio: 100,
            buffer: VecDeque::new(),
        }
    }

    /// Creates a loopback interface
    pub fn loopback() -> Self {
        Interface {
            name: "lo0".into(),
            device: NetworkDevice::loopback(),
            flags: InterfaceFlags::loopback(),
            addrs: InterfaceAddrs::new(Vec::from(InterfaceAddr::loopback())),
            status: InterfaceStatus::Active,
            prio: 100,
            state: InterfaceBusyState::Idle,
            buffer: VecDeque::new(),
        }
    }

    pub(super) fn add_write_interest(&mut self, fd: Fd) {
        if let InterfaceBusyState::Busy { interests, .. } = &mut self.state {
            interests.push(fd);
        }
    }

    pub fn ipv4_subnet(&self) -> Option<(Ipv4Addr, Ipv4Addr)> {
        self.addrs.iter().find_map(|a| {
            if let InterfaceAddr::Inet { addr, netmask } = a {
                Some((*addr, *netmask))
            } else {
                None
            }
        })
    }

    pub fn ipv6_subnet(&self) -> Option<(Ipv6Addr, Ipv6Addr)> {
        self.addrs.iter().find_map(|addr| {
            if let InterfaceAddr::Inet6(addr) = addr {
                Some((addr.addr, addr.mask))
            } else {
                None
            }
        })
    }

    pub(crate) fn send_buffered(&mut self, msg: Message) -> Result<()> {
        if self.is_busy() {
            // if self.buffer.len() >= 16 {
            //     return Err(Error::new(ErrorKind::Other, "interface busy, buffer fullö"));
            // }

            self.buffer.push_back(msg);
            Ok(())
        } else {
            self.send(msg)
        }
    }

    pub(crate) fn send(&mut self, msg: Message) -> Result<()> {
        if self.state != InterfaceBusyState::Idle {
            return Err(Error::new(
                ErrorKind::WouldBlock,
                "interface is busy - would block",
            ));
        }

        #[cfg(feature = "libpcap")]
        crate::libpcap::capture(crate::libpcap::PcapEnvelope {
            capture: crate::libpcap::PcapCapturePoint::Egress,
            message: &msg,
            iface: &self,
        });

        self.state = self.device.send(msg);
        self.schedule_link_update();

        Ok(())
    }

    pub(crate) fn schedule_link_update(&self) {
        if let InterfaceBusyState::Busy { until, .. } = &self.state {
            schedule_at(Message::from(LinkUpdate(self.name.id)), *until);
        }
    }

    pub(crate) fn recv_link_update(&mut self) -> Vec<Fd> {
        assert!(!self.device.is_busy(), "Link notif send invalid message");
        if let Some(msg) = self.buffer.pop_front() {
            // still busy with link layer events.
            #[cfg(feature = "libpcap")]
            crate::libpcap::capture(crate::libpcap::PcapEnvelope {
                capture: crate::libpcap::PcapCapturePoint::Egress,
                message: &msg,
                iface: &self,
            });

            self.state.merge_new(self.device.send(msg));
            self.schedule_link_update();

            Vec::new()
        } else {
            // finally unbusy, so networking layer can continue to work.
            let mut swap = InterfaceBusyState::Idle;
            std::mem::swap(&mut swap, &mut self.state);

            let InterfaceBusyState::Busy { interests, .. } = swap else {
                panic!("Huh failure")
            };
            interests
        }
    }

    pub fn is_busy(&self) -> bool {
        matches!(self.state, InterfaceBusyState::Busy { .. })
    }

    fn valid_recv_addr(&self, addr: MacAddress) -> bool {
        if addr.is_broadcast() {
            return true;
        }
        if addr == self.device.addr {
            return true;
        }

        // tracing::info!(
        //     "{addr} in {:#?}",
        //     self.addrs
        //         .v6_multicast
        //         .iter()
        //         .map(|b| MacAddress::ipv6_multicast(b.addr).to_string() + &b.to_string())
        //         .collect::<Vec<_>>()
        // );

        // Check multicast scopes
        if self
            .addrs
            .v6_multicast
            .iter()
            .any(|scope| MacAddress::ipv6_multicast(scope.addr) == addr)
        {
            return true;
        }

        false
    }
}

impl IOContext {
    pub fn recv_linklayer(&mut self, msg: Message) -> LinkLayerResult {
        use LinkLayerResult::*;
        let dst = MacAddress::from(msg.header().dest);

        // Precheck for link layer updates
        if msg.header().kind == KIND_LINK_UPDATE {
            let Some(&update) = msg.try_content::<LinkUpdate>() else {
                tracing::error!(
                    "found message with kind KIND_LINK_UPDATE, did not contain link updates"
                );
                return PassThrough(msg);
            };
            self.recv_linklayer_update(update);

            return Consumed();
        }

        if msg.header().kind == KIND_IO_TIMEOUT {
            // TODO: check ARP Timeout
            if msg.header().id == KIND_ARP {
                self.recv_arp_wakeup();
                return Consumed();
            }

            return Timeout(msg);
        }

        // Define the physical device the packet arrived.
        let Some((ifid, iface)) = self.device_for_message(&msg) else {
            return PassThrough(msg);
        };

        // Capture all packets that can be addressed to a interface, event not targeted
        let ifid = *ifid;

        #[cfg(feature = "libpcap")]
        crate::libpcap::capture(crate::libpcap::PcapEnvelope {
            capture: crate::libpcap::PcapCapturePoint::Ingress,
            message: &msg,
            iface: iface,
        });

        // Check that packet is addressed correctly.

        if !iface.valid_recv_addr(dst) {
            if dst.is_multicast() {
                return Consumed();
            } else {
                tracing::warn!(IFACE=%ifid, "recieved invalid LL packet {{ dst: {dst} }}");
                return PassThrough(msg);
            }
        }

        if msg.header().kind == KIND_ARP {
            let Some(arp) = msg.try_content::<ArpPacket>() else {
                tracing::error!(
                    "found message with kind 0x0806 (arp), but did not contain ARP packet"
                );
                return PassThrough(msg);
            };

            return self.recv_arp(ifid, &msg, arp);
        }

        NetworkingPacket(msg, ifid)
    }

    fn recv_linklayer_update(&mut self, update: LinkUpdate) {
        let Some(iface) = self.ifaces.get_mut(&update.0) else {
            return;
        };

        let ifid = iface.name.id;
        let fds = iface.recv_link_update();
        for fd in fds {
            self.socket_link_update(fd, ifid);
        }
    }

    fn device_for_message(&self, msg: &Message) -> Option<(&IfId, &Interface)> {
        self.ifaces
            .iter()
            .find(|(_, iface)| iface.device.last_gate_matches(&msg.header().last_gate))
    }

    pub(super) fn get_iface(&self, ifid: IfId) -> io::Result<&Interface> {
        self.ifaces.get(&ifid).ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "no interface found under this id")
        })
    }
    pub(super) fn get_mut_iface(&mut self, ifid: IfId) -> io::Result<&mut Interface> {
        self.ifaces.get_mut(&ifid).ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "no interface found under this id")
        })
    }
}
