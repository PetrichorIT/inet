//! Network interfaces and Network devices.
//!
//!

use std::{
    collections::VecDeque,
    io::{self, Error, ErrorKind, Result},
};

use crate::{arp::ArpEntryInternal, IOContext};
use crate::{
    routing::Ipv6RoutingPrefix,
    socket::{Fd, SocketIfaceBinding},
};
use bytepack::ToBytestream;
use des::prelude::*;
use fxhash::{FxBuildHasher, FxHashMap};
use inet_types::{
    arp::ArpPacket,
    icmpv6::{IcmpV6RouterAdvertisement, PROTO_ICMPV6},
    ip::{ipv6_merge_mac, IPV6_MULTICAST_ALL_ROUTERS},
};
use inet_types::{
    arp::KIND_ARP,
    icmpv6::{IcmpV6NDPOption, IcmpV6Packet, IcmpV6RouterSolicitation},
};
use inet_types::{
    iface::MacAddress,
    ip::{IpPacket, Ipv6Packet},
};

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
    pub addrs: Vec<InterfaceAddr>,
    /// The internal state of the interface
    pub status: InterfaceStatus,
    /// A flag indicating whether the interface is currently busy sending
    pub state: InterfaceBusyState,

    pub(crate) prio: usize,
    pub(crate) buffer: VecDeque<Message>,
}

pub(crate) struct InterfaceMngmt {
    v6_cfg: FxHashMap<IfId, InterfaceV6Configuration>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct InterfaceV6Configuration {
    router_solictation_request: Option<SimTime>, // Timeout for solicitation
    router_solicitation: Option<RouterSolicitation>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RouterSolicitation {
    resp: IcmpV6RouterAdvertisement,
    prefixes: Vec<Ipv6RoutingPrefix>,
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
    pub(crate) fn link_local_v6(&self) -> Option<Ipv6Addr> {
        for addr in &self.addrs {
            if let InterfaceAddr::Inet6 {
                addr, prefixlen, ..
            } = addr
            {
                let addr = u128::from(*addr);
                let link_local_prefix = 0xfe80_0000_0000_0000_0000_0000_0000_0000u128;
                let mask = u128::MAX << 64;
                if (addr & mask == link_local_prefix) && *prefixlen == 64 {
                    return Some(Ipv6Addr::from(addr));
                }
            }
        }
        None
    }

    pub fn ethv6_autocfg(device: NetworkDevice) -> Self {
        let link_local = InterfaceAddr::ipv6_link_local(device.addr);
        Self {
            name: InterfaceName::new("en0"),
            device,
            flags: InterfaceFlags::en0(),
            addrs: vec![link_local],
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
            flags: InterfaceFlags::en0(),
            addrs: vec![
                InterfaceAddr::Inet {
                    addr: v4.0,
                    netmask: v4.1,
                },
                InterfaceAddr::Inet6 {
                    addr: v6.0,
                    prefixlen: v6.1,
                    scope_id: None,
                },
            ],
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
}

impl InterfaceMngmt {
    pub(super) fn new() -> Self {
        Self {
            v6_cfg: FxHashMap::with_hasher(FxBuildHasher::default()),
        }
    }

    fn store_router_solicitation_timeout(&mut self, ifid: IfId, timeout: SimTime) {
        self.v6_cfg
            .get_mut(&ifid)
            .expect("Interface not found")
            .router_solictation_request = Some(timeout);
    }
}

impl IOContext {
    pub fn recv_linklayer(&mut self, msg: Message) -> LinkLayerResult {
        use LinkLayerResult::*;
        let dest = MacAddress::from(msg.header().dest);

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
        if iface.device.addr != dest && !dest.is_broadcast() {
            return PassThrough(msg);
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

    fn register_v6_interface(&mut self, ifid: IfId) -> io::Result<()> {
        let iface = self.get_iface(ifid)?;
        let iface_mac = iface.device.addr;
        let iface_ll = iface
            .link_local_v6()
            .expect("no link local address configured ??");

        tracing::trace!(
            IFACE=%ifid,
            MAC=%iface_mac,
            IP=%iface_ll,
            "registered for stateless autocfg"
        );

        self.iface_mngmt
            .v6_cfg
            .insert(ifid, InterfaceV6Configuration::default());

        // Send inital router solictation
        let router_solicitation = IcmpV6Packet::RouterSolicitation(IcmpV6RouterSolicitation {
            options: vec![IcmpV6NDPOption::SourceLinkLayerAddress(iface_mac)],
        });

        let pkt = IpPacket::V6(Ipv6Packet {
            traffic_class: 0,
            flow_label: 0,
            next_header: PROTO_ICMPV6,
            hop_limit: 32,
            src: iface_ll,
            dest: IPV6_MULTICAST_ALL_ROUTERS,
            content: router_solicitation.to_vec()?,
        });

        self.send_ip_packet(SocketIfaceBinding::Bound(ifid), pkt, true)?;
        let timeout = SimTime::now() + Duration::from_secs(30);
        self.iface_mngmt
            .store_router_solicitation_timeout(ifid, timeout);

        Ok(())
    }

    pub(super) fn v6_interface_process_router_adv(
        &mut self,
        ifid: IfId,
        adv: IcmpV6RouterAdvertisement,
    ) {
        let iface = self.get_iface(ifid).unwrap();
        let mac = iface.device.addr;

        let mngm = self.iface_mngmt.v6_cfg.get(&ifid).unwrap();
        let old_prefixes = mngm
            .router_solicitation
            .as_ref()
            .map(|sol| sol.prefixes.clone())
            .unwrap_or(Vec::new());
        let mut new_prefixes = Vec::new();

        for option in &adv.options {
            match option {
                IcmpV6NDPOption::PrefixInformation(pi) => {
                    if pi.autonomous_address_configuration {
                        new_prefixes.push(Ipv6RoutingPrefix {
                            prefix_len: pi.prefix_len,
                            prefix: pi.prefix,
                        })
                    }
                }
                _ => {}
            }
        }

        let removed_prefixes = old_prefixes.iter().filter(|p| !new_prefixes.contains(p));
        for _prefix in removed_prefixes {
            // TODO
        }

        let new_prefixes = new_prefixes.iter().filter(|p| !old_prefixes.contains(p));
        for prefix in new_prefixes {
            let gen_addr = ipv6_merge_mac(prefix.prefix, mac);

            tracing::trace!(IFACE=%ifid, MAC=%mac, IP=%gen_addr, "stateless configuration assigned address");

            let _ = self.arp.update(ArpEntryInternal {
                negated: false,
                hostname: Some(current().name()),
                ip: IpAddr::V6(gen_addr),
                mac,
                iface: ifid,
                expires: SimTime::MAX,
            });
        }
    }
}
