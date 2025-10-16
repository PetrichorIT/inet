//! Network interfaces and Network devices.
//!
//!

use std::borrow::Borrow;
use std::hash::Hash;
use std::io;
use std::{collections::VecDeque, result};

use crate::IOContext;
use crate::{ctx::LinkLayerResult, socket::Fd};
use des::prelude::*;
use fxhash::FxHashMap;
use tokio::sync::watch;
use types::arp::ArpPacket;
use types::arp::KIND_ARP;
use types::iface::MacAddress;

mod def;
pub use self::def::*;

mod api;

mod device;
pub use self::device::*;

mod util;
pub use self::util::*;

mod flags;
pub use flags::*;

mod addrs;
pub use self::addrs::*;

mod handle;
pub use self::handle::*;

#[derive(Debug, Default)]
pub struct Interfaces {
    map: FxHashMap<IfId, InterfaceController>,
}

impl Interfaces {
    pub fn contains_key<Q>(&self, k: &Q) -> bool
    where
        IfId: Borrow<Q>,
        Q: Hash + Eq,
    {
        self.map.contains_key(k)
    }

    pub fn get<Q>(&self, k: &Q) -> Option<&InterfaceController>
    where
        IfId: Borrow<Q>,
        Q: Hash + Eq,
    {
        self.map.get(k)
    }

    pub fn get_mut<Q>(&mut self, k: &Q) -> Option<&mut InterfaceController>
    where
        IfId: Borrow<Q>,
        Q: Hash + Eq,
    {
        self.map.get_mut(k)
    }

    pub fn get_mut_spec(&mut self, k: &IfSpec) -> Option<&mut InterfaceController> {
        k.and_then(|k| self.map.get_mut(&k))
    }

    pub fn add(&mut self, iface: InterfaceController) {
        self.map.insert(iface.name.id(), iface);
    }

    pub fn keys(&self) -> impl Iterator<Item = IfId> {
        self.map.keys().copied()
    }

    pub fn values(&self) -> impl Iterator<Item = &InterfaceController> {
        self.map.values()
    }

    pub fn values_mut(&mut self) -> impl Iterator<Item = &mut InterfaceController> {
        self.map.values_mut()
    }
}

/// A network interface, mapping a physical network device
/// to internal abstractions
#[derive(Debug)]
pub struct InterfaceController {
    pub name: InterfaceName,
    pub device: NetworkDevice,
    pub flags: InterfaceFlags,
    pub bindings: InterfaceAddrBindings,
    pub state: InterfaceState,
}

#[derive(Debug)]
pub struct InterfaceState {
    pub busy: InterfaceBusyState,
    pub prio: usize,
    pub send_q: usize,
    pub buffer: VecDeque<Message>,
    pub events: watch::Sender<InterfaceEvent>,
}

#[derive(Debug, Clone)]
pub enum InterfaceEvent {
    Up,
    AddrUp(IpAddr),
}

impl Default for InterfaceState {
    fn default() -> Self {
        Self {
            busy: InterfaceBusyState::Idle,
            prio: 200,
            send_q: 0,
            buffer: VecDeque::new(),
            events: watch::channel(InterfaceEvent::Up).0,
        }
    }
}

#[derive(Debug)]
pub enum InterfaceError {
    PacketToBig(Message, usize),
}

impl InterfaceController {
    pub fn id(&self) -> IfId {
        self.name.id()
    }

    pub fn status(&self) -> InterfaceStatus {
        InterfaceStatus {
            name: self.name.clone(),
            flags: self.flags,
            addrs: self.bindings.clone(),
            send_q: self.state.send_q,
            queuelen: self.state.buffer.len(),
        }
    }

    pub fn empty(name: &str, device: NetworkDevice) -> Self {
        Self {
            name: InterfaceName::new(name),
            device,
            flags: InterfaceFlags::en0(true),
            bindings: InterfaceAddrBindings::default(),
            state: InterfaceState::default(),
        }
    }

    pub(super) fn add_write_interest(&mut self, fd: Fd) {
        if let InterfaceBusyState::Busy { interests, .. } = &mut self.state.busy {
            interests.push(fd);
        }
    }

    pub fn ipv4_subnet(&self) -> Option<(Ipv4Addr, Ipv4Addr)> {
        self.bindings.v4.unicast.first().map(|b| (b.addr, b.mask))
    }

    pub fn ipv6_subnet(&self) -> Option<(Ipv6Addr, Ipv6Addr)> {
        self.bindings.v6.unicast.first().map(|b| (b.addr, b.mask))
    }

    pub(crate) fn send_buffered(&mut self, msg: Message) -> Result<(), InterfaceError> {
        if msg.body.length() > self.device.mtu() {
            return Err(InterfaceError::PacketToBig(msg, self.device.mtu()));
        }

        if self.is_busy() {
            self.state.buffer.push_back(msg);
            Ok(())
        } else {
            match self.send_raw(msg) {
                Ok(()) => Ok(()),
                Err(msg) => {
                    self.state.buffer.push_back(msg);
                    Ok(())
                }
            }
        }
    }

    fn send_raw(&mut self, msg: Message) -> result::Result<(), Message> {
        assert!(
            msg.body.length() <= self.device.mtu(),
            "should have been checked before in send()"
        );

        match self.device.ready() {
            NetworkDeviceReadiness::Ready => {
                #[cfg(feature = "libpcap")]
                crate::libpcap::capture(crate::libpcap::PcapEnvelope {
                    capture: crate::libpcap::PcapCapturePoint::Egress,
                    message: &msg,
                    iface: self,
                });
            }
            NetworkDeviceReadiness::Busy(until) => {
                self.state.busy.merge_new(InterfaceBusyState::Busy {
                    until,
                    interests: Vec::new(),
                });
                self.schedule_link_update();
                return Err(msg);
            }
        }

        self.state.busy.merge_new(self.device.send(msg).into());
        self.state.send_q += 1;
        self.schedule_link_update();
        self.status().publish();

        Ok(())
    }

    pub(crate) fn schedule_link_update(&self) {
        if let InterfaceBusyState::Busy { until, .. } = &self.state.busy {
            schedule_at(Message::from(LinkUpdate(self.name.id())), *until);
        }
    }

    pub(crate) fn recv_link_update(&mut self) -> Vec<Fd> {
        if let Some(msg) = self.state.buffer.pop_front() {
            match self.send_raw(msg) {
                Ok(()) => Vec::new(),
                Err(msg) => {
                    self.state.buffer.push_front(msg);
                    Vec::new()
                }
            }
        } else {
            // finally unbusy, so networking layer can continue to work.
            let mut swap = InterfaceBusyState::Idle;
            std::mem::swap(&mut swap, &mut self.state.busy);

            let InterfaceBusyState::Busy { interests, .. } = swap else {
                panic!("Huh failure")
            };
            interests
        }
    }

    pub fn is_busy(&self) -> bool {
        matches!(self.state.busy, InterfaceBusyState::Busy { .. })
    }

    pub fn is_valid_recv_addr(&self, addr: MacAddress) -> bool {
        if addr.is_broadcast() {
            return true;
        }
        if addr == self.device.addr {
            return true;
        }
        // Check multicast scopes
        if self.bindings.v6.valid_src_mac(addr) {
            return true;
        }
        false
    }
}

impl From<InterfaceError> for io::Error {
    fn from(value: InterfaceError) -> Self {
        match value {
            InterfaceError::PacketToBig(pkt, allowed) => io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("packet to big {} > {}", pkt.body.length(), allowed),
            ),
        }
    }
}

impl IOContext {
    pub fn recv_linklayer(&mut self, msg: Message) -> LinkLayerResult {
        use LinkLayerResult::*;

        let dst = MacAddress::from(msg.dst);

        // Precheck for link layer updates
        if msg.header.kind == KIND_LINK_UPDATE {
            let Some(update) = msg.body.try_content::<LinkUpdate>() else {
                tracing::error!(
                    "found message with kind KIND_LINK_UPDATE, did not contain link updates"
                );
                return PassThrough(msg);
            };
            self.recv_linklayer_update(update);
            return Consumed();
        }

        if msg.header.kind == KIND_IO_TIMEOUT {
            // TODO: check ARP Timeout
            if msg.header.id == KIND_ARP {
                self.recv_arp_wakeup();
                return Consumed();
            }
            return Timeout(msg);
        }

        // Define the physical device the packet arrived.
        let Some(iface) = self.device_for_message(&msg) else {
            return PassThrough(msg);
        };

        // Capture all packets that can be addressed to a interface, event not targeted
        let ifid = iface.id();

        #[cfg(feature = "libpcap")]
        crate::libpcap::capture(crate::libpcap::PcapEnvelope {
            capture: crate::libpcap::PcapCapturePoint::Ingress,
            message: &msg,
            iface,
        });

        // Check that packet is addressed correctly.

        if !iface.is_valid_recv_addr(dst) {
            if dst.is_multicast() {
                return Consumed();
            } else {
                tracing::warn!(IFACE=%ifid, "recieved invalid LL packet {{ dst: {dst} }}");
                return PassThrough(msg);
            }
        }

        if msg.header.kind == KIND_ARP {
            let Some(arp) = msg.body.try_content::<ArpPacket>() else {
                tracing::error!(
                    "found message with kind 0x0806 (arp), but did not contain ARP packet"
                );
                return PassThrough(msg);
            };

            return self.recv_arp(ifid, &msg, arp);
        }

        NetworkingPacket(msg, ifid)
    }

    fn recv_linklayer_update(&mut self, update: &LinkUpdate) {
        let Some(iface) = self.ifaces.get_mut(&update.0) else {
            return;
        };

        let ifid = iface.name.id();
        let fds = iface.recv_link_update();
        for fd in fds {
            self.socket_link_update(fd, ifid);
        }
    }

    fn device_for_message(&self, msg: &Message) -> Option<&InterfaceController> {
        self.ifaces
            .values()
            .find(|iface| iface.device.matches(&msg.header))
    }

    pub(super) fn get_iface(&self, ifid: IfId) -> io::Result<&InterfaceController> {
        self.ifaces.get(&ifid).ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "no interface found under this id")
        })
    }
    pub(super) fn get_mut_iface(&mut self, ifid: IfId) -> io::Result<&mut InterfaceController> {
        self.ifaces.get_mut(&ifid).ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "no interface found under this id")
        })
    }
}
