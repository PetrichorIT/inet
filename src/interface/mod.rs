use std::collections::VecDeque;
use std::io;
use std::io::Error;
use std::io::ErrorKind;

use crate::arp::ARPPacket;
use crate::arp::KIND_ARP;
use crate::socket::Fd;
use crate::IOContext;
use des::prelude::*;

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

mod mac;
pub use self::mac::*;

mod types;
pub use self::types::*;

mod flags;
pub use flags::*;

mod addrs;
pub use self::addrs::*;

#[derive(Debug)]
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
    pub(crate) buffer: VecDeque<Message>,
}

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
    pub fn eth(device: NetworkDevice, ip: IpAddr) -> Interface {
        match ip {
            IpAddr::V4(v4) => Self::ethv4(device, v4),
            IpAddr::V6(v6) => Self::ethv6(device, v6),
        }
    }

    pub fn ethv4(device: NetworkDevice, v4: Ipv4Addr) -> Interface {
        Self::ethv4_named("en0", device, v4, Ipv4Addr::new(255, 255, 255, 0))
    }

    pub fn ethv6(device: NetworkDevice, v6: Ipv6Addr) -> Interface {
        Self::ethv6_named("en1", device, v6)
    }

    pub fn ethv6_named(
        name: impl AsRef<str>,
        device: NetworkDevice,
        subnet: Ipv6Addr,
    ) -> Interface {
        Interface {
            name: InterfaceName::new(name),
            device,
            flags: InterfaceFlags::en0(),
            addrs: vec![InterfaceAddr::Inet6 {
                addr: subnet,
                prefixlen: 64,
                scope_id: None,
            }],
            status: InterfaceStatus::Active,
            state: InterfaceBusyState::Idle,
            prio: 200,
            buffer: VecDeque::new(),
        }
    }

    pub fn ethv4_named(
        name: impl AsRef<str>,
        device: NetworkDevice,
        subnet: Ipv4Addr,
        mask: Ipv4Addr,
    ) -> Interface {
        Interface {
            name: InterfaceName::new(name),
            device,
            flags: InterfaceFlags::en0(),
            addrs: vec![InterfaceAddr::Inet {
                addr: subnet,
                netmask: mask,
            }],
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
            addrs: Vec::from(InterfaceAddr::loopback()),
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
        self.addrs.iter().find_map(|a| {
            if let InterfaceAddr::Inet6 {
                addr, prefixlen, ..
            } = a
            {
                let mask = Ipv6Addr::from(!(u128::MAX.overflowing_shr(*prefixlen as u32).0));
                Some((*addr, mask))
            } else {
                None
            }
        })
    }

    pub fn send_buffered(&mut self, msg: Message) -> io::Result<()> {
        if self.is_busy() {
            self.buffer.push_back(msg);
            Ok(())
        } else {
            self.send(msg)
        }
    }

    pub fn send(&mut self, msg: Message) -> io::Result<()> {
        if self.state != InterfaceBusyState::Idle {
            return Err(Error::new(
                ErrorKind::WouldBlock,
                "interface is busy - would block",
            ));
        }

        self.state = self.device.send(msg);
        self.schedule_link_update();

        Ok(())
    }

    pub fn schedule_link_update(&self) {
        if let InterfaceBusyState::Busy { until, .. } = &self.state {
            schedule_at(Message::from(LinkUpdate(self.name.id)), *until);
        }
    }

    pub fn recv_link_update(&mut self) -> Vec<Fd> {
        assert!(!self.device.is_busy(), "Link notif send invalid message");
        if let Some(msg) = self.buffer.pop_front() {
            // still busy with link layer events.
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
}

impl IOContext {
    pub fn recv_linklayer(&mut self, msg: Message) -> LinkLayerResult {
        use LinkLayerResult::*;
        let dest = MacAddress::from(msg.header().dest);

        // Precheck for link layer updates
        if msg.header().kind == KIND_LINK_UPDATE {
            let Some(&update) = msg.try_content::<LinkUpdate>() else {
                log::error!(target: "inet/link", "found message with kind KIND_LINK_UPDATE, did not contain link updates");
                return PassThrough(msg)
            };
            self.recv_linklayer_update(update);

            return Consumed();
        }

        if msg.header().kind == KIND_IO_TIMEOUT {
            // TODO: check ARP Timeout
            return Timeout(msg);
        }

        // Define the physical device the packet arrived.
        let Some((ifid, iface)) = self.device_for_message(&msg) else {
            return PassThrough(msg)
        };

        // Check that packet is addressed correctly.
        if iface.device.addr != dest && !dest.is_broadcast() {
            return PassThrough(msg);
        }

        let ifid = *ifid;
        if msg.header().kind == KIND_ARP {
            let Some(arp) = msg.try_content::<ARPPacket>() else {
                log::error!(target: "inet/arp", "found message with kind 0x0806 (arp), but did not contain ARP packet");
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
}
