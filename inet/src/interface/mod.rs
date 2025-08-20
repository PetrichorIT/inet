//! Network interfaces and Network devices.
//!
//!

use std::{
    collections::VecDeque,
    io::{self, Error, ErrorKind, Result},
    result,
};

use crate::IOContext;
use crate::{ctx::LinkLayerResult, socket::Fd};
use des::prelude::*;
use types::arp::ArpPacket;
use types::arp::KIND_ARP;
use types::iface::MacAddress;

mod def;
pub use self::def::*;

mod api;
pub use self::api::*;

mod device;
pub use self::device::*;

mod util;
pub use self::util::*;

mod flags;
pub use flags::*;

mod addrs;
pub use self::addrs::*;

/// A network interface, mapping a physical network device
/// to internal abstractions
#[derive(Debug)]
pub struct InterfaceController {
    pub name: InterfaceName,
    pub device: NetworkDevice,
    pub flags: InterfaceFlags,
    pub bindings: InterfaceAddrBindings,
    pub state: InterfaceBusyState,
    pub prio: usize,
    pub buffer: VecDeque<Message>,
    pub send_q: usize,
}

impl InterfaceController {
    pub fn status(&self) -> InterfaceStatus {
        InterfaceStatus {
            name: self.name.clone(),
            flags: self.flags,
            addrs: self.bindings.clone(),
            send_q: self.send_q,
            queuelen: self.buffer.len(),
        }
    }

    pub fn empty(name: &str, device: NetworkDevice) -> Self {
        Self {
            name: InterfaceName::new(name),
            device,
            flags: InterfaceFlags::en0(true),
            bindings: InterfaceAddrBindings::default(),
            state: InterfaceBusyState::Idle,
            prio: 200,
            buffer: VecDeque::new(),
            send_q: 0,
        }
    }

    pub(super) fn add_write_interest(&mut self, fd: Fd) {
        if let InterfaceBusyState::Busy { interests, .. } = &mut self.state {
            interests.push(fd);
        }
    }

    pub fn ipv4_subnet(&self) -> Option<(Ipv4Addr, Ipv4Addr)> {
        self.bindings.v4.unicast.first().map(|b| (b.addr, b.mask))
    }

    pub fn ipv6_subnet(&self) -> Option<(Ipv6Addr, Ipv6Addr)> {
        self.bindings.v6.unicast.first().map(|b| (b.addr, b.mask))
    }

    pub(crate) fn send_buffered(&mut self, msg: Message) -> Result<()> {
        if self.is_busy() {
            // if self.buffer.len() >= 16 {
            //     return Err(Error::new(ErrorKind::Other, "interface busy, buffer fullö"));
            // }
            self.buffer.push_back(msg);
            Ok(())
        } else {
            match self.send_raw(msg) {
                Ok(()) => Ok(()),
                Err(msg) => {
                    self.buffer.push_back(msg);
                    Ok(())
                }
            }
        }
    }

    pub(crate) fn send(&mut self, msg: Message) -> Result<()> {
        if self.state != InterfaceBusyState::Idle {
            return Err(Error::new(
                ErrorKind::WouldBlock,
                "interface is busy - would block",
            ));
        }

        match self.send_raw(msg) {
            Ok(()) => Ok(()),
            Err(_) => Err(Error::new(
                ErrorKind::WouldBlock,
                "interface is busy - would block",
            )),
        }
    }

    fn send_raw(&mut self, msg: Message) -> result::Result<(), Message> {
        match self.device.ready() {
            NetworkDeviceReadiness::Ready => {
                #[cfg(feature = "libpcap")]
                crate::libpcap::capture(crate::libpcap::PcapEnvelope {
                    capture: crate::libpcap::PcapCapturePoint::Egress,
                    message: &msg,
                    iface: &self,
                });
            }
            NetworkDeviceReadiness::Busy(until) => {
                self.state.merge_new(InterfaceBusyState::Busy {
                    until,
                    interests: Vec::new(),
                });
                self.schedule_link_update();
                return Err(msg);
            }
        }

        self.state.merge_new(self.device.send(msg).into());
        self.send_q += 1;
        self.schedule_link_update();
        self.status().publish();

        Ok(())
    }

    pub(crate) fn schedule_link_update(&self) {
        if let InterfaceBusyState::Busy { until, .. } = &self.state {
            schedule_at(Message::from(LinkUpdate(self.name.id())), *until);
        }
    }

    pub(crate) fn recv_link_update(&mut self) -> Vec<Fd> {
        if let Some(msg) = self.buffer.pop_front() {
            match self.send_raw(msg) {
                Ok(()) => Vec::new(),
                Err(msg) => {
                    self.buffer.push_front(msg);
                    Vec::new()
                }
            }
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

impl IOContext {
    pub fn recv_linklayer(&mut self, msg: Message) -> LinkLayerResult {
        use LinkLayerResult::*;

        let dst = MacAddress::from(msg.dst);

        // Precheck for link layer updates
        if msg.header().kind == KIND_LINK_UPDATE {
            let Some(update) = msg.body.try_content::<LinkUpdate>() else {
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
        let ifid = ifid.clone();

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

        if msg.header().kind == KIND_ARP {
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
            self.socket_link_update(fd, ifid.clone());
        }
    }

    fn device_for_message(&self, msg: &Message) -> Option<(&IfId, &InterfaceController)> {
        self.ifaces
            .iter()
            .find(|(_, iface)| iface.device.last_gate_matches(&msg.header().last_gate))
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
