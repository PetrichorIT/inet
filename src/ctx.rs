use crate::{
    arp::{ARPConfig, ARPTable},
    interface::{IfId, Interface, LinkLayerResult, KIND_LINK_UPDATE},
    ip::{IpPacket, IpPacketRef, Ipv4Packet, Ipv6Packet, KIND_IPV4, KIND_IPV6},
    routing::{Ipv4RoutingTable, Ipv6RoutingTable},
    IOPlugin,
};
use des::{net::plugin::PluginError, prelude::Message};
use std::{
    cell::RefCell,
    collections::HashMap,
    net::{IpAddr, Ipv4Addr},
    panic::UnwindSafe,
    time::Duration,
};

use super::{
    socket::*,
    tcp::{api::TcpListenerHandle, TcpController, PROTO_TCP},
    udp::{UdpManager, PROTO_UDP},
};

thread_local! {
    static CURRENT: RefCell<Option<IOContext>> = const { RefCell::new(None) };
}

pub struct IOContext {
    pub(super) ifaces: HashMap<IfId, Interface>,

    pub(super) arp: ARPTable,
    pub(super) ipv4router: Ipv4RoutingTable,
    pub(super) ipv6router: Ipv6RoutingTable,

    pub(super) sockets: HashMap<Fd, Socket>,

    pub(super) udp_manager: HashMap<Fd, UdpManager>,
    pub(super) tcp_manager: HashMap<Fd, TcpController>,
    pub(super) tcp_listeners: HashMap<Fd, TcpListenerHandle>,

    pub(super) fd: Fd,
    pub(super) port: u16,
}

impl IOContext {
    pub fn empty() -> Self {
        Self {
            ifaces: HashMap::new(),

            arp: ARPTable::new(),
            ipv4router: Ipv4RoutingTable::new(),
            ipv6router: Ipv6RoutingTable::new(),

            sockets: HashMap::new(),

            udp_manager: HashMap::new(),
            tcp_manager: HashMap::new(),
            tcp_listeners: HashMap::new(),

            fd: 100,
            port: 1024,
        }
    }

    // pub fn loopback_only() -> Self {
    //     let mut this = Self::empty();
    //     this.add_interface2(Interface::loopback());
    //     this
    // }

    // pub fn eth_default(v4: Ipv4Addr) -> Self {
    //     Self::eth_with_addr(v4, random())
    // }

    // pub fn eth_with_addr(v4: Ipv4Addr, mac: [u8; 6]) -> Self {
    //     let mut this = Self::empty();
    //     this.add_interface2(Interface::loopback());
    //     this.add_interface2(Interface::en0(mac, v4, NetworkDevice::eth_default()));
    //     this
    // }

    pub fn set(self) {
        Self::swap_in(Some(self));
    }

    pub(super) fn swap_in(ingoing: Option<IOContext>) -> Option<IOContext> {
        CURRENT.with(|ctx| {
            let mut ctx = ctx.borrow_mut();
            let ret = ctx.take();
            *ctx = ingoing;
            ret
        })
    }

    pub(super) fn with_current<R>(f: impl FnOnce(&mut IOContext) -> R) -> R {
        CURRENT.with(|cell| {
            f(cell.borrow_mut().as_mut().unwrap_or_else(|| {
                let error = PluginError::expected::<IOPlugin>();
                panic!("Missing IOContext: {error}")
            }))
        })
    }

    pub(super) fn try_with_current<R>(f: impl FnOnce(&mut IOContext) -> R) -> Option<R> {
        match CURRENT.try_with(|cell| {
            Some(f(cell
                .try_borrow_mut()
                .expect("BorrowMut at IOContext")
                .as_mut()?))
        }) {
            Ok(v) => v,
            Err(_) => None,
        }
    }
}

impl IOContext {
    pub fn recv(&mut self, msg: Message) -> Option<Message> {
        use LinkLayerResult::*;

        // Packets that are passed to the networking layer, are
        // not nessecarily addressed to any valid ip addr, but are valid for
        // the local MAC addr
        let l2 = self.recv_linklayer(msg);
        // log::debug!("- {l2:?}");
        let (msg, ifid) = match l2 {
            PassThrough(msg) => return Some(msg),
            Consumed() => return None,
            NetworkingPacket(msg, ifid) => (msg, ifid),
            Timeout(timeout) => return self.networking_layer_io_timeout(timeout),
        };

        let kind = msg.header().kind;
        match kind {
            KIND_IPV4 => {
                let Some(ip) = msg.try_content::<Ipv4Packet>() else {
                    log::error!(target: "inet", "received eth-packet with kind=0x0800 (ip) but content was no ipv4-packet");
                    return Some(msg)
                };

                let iface = self.ifaces.get(&ifid).unwrap();

                // (0) Check whether the received ip packet is addressed for the local machine
                let local_dest = ip.dest == Ipv4Addr::BROADCAST
                    || iface
                        .addrs
                        .iter()
                        .any(|addr| addr.matches_ip(IpAddr::V4(ip.dest)));
                if !local_dest {
                    // (0) Check TTL
                    let mut pkt = ip.clone();
                    pkt.ttl = pkt.ttl.saturating_sub(1);

                    if pkt.ttl == 0 {
                        log::warn!(target: "inet/route", "dropping packet due to ttl");
                        return None;
                    }

                    // (2) Reroute packet.
                    match self.send_ip_packet(
                        SocketIfaceBinding::Any(self.ifaces.keys().copied().collect()),
                        IpPacket::V4(pkt),
                        true,
                    ) {
                        Ok(()) => return None,
                        Err(e) => panic!("not yet impl: forwarding without route: {}", e),
                    };
                }

                match ip.proto {
                    0 => return Some(msg),
                    PROTO_UDP => {
                        let consumed = self.recv_udp_packet(IpPacketRef::V4(ip), ifid);
                        if consumed {
                            None
                        } else {
                            Some(msg)
                        }
                    }
                    PROTO_TCP => {
                        let consumed = self.capture_tcp_packet(IpPacketRef::V4(ip), todo!());
                        if consumed {
                            None
                        } else {
                            Some(msg)
                        }
                    }
                    k => panic!("internal error: unreachable code :: proto = {k}"),
                }
            }
            KIND_IPV6 => {
                let Some(ip) = msg.try_content::<Ipv6Packet>() else {
                    log::error!(target: "inet", "received eth-packet with kind=0x0800 (ip) but content was no ipv4-packet");
                    return Some(msg)
                };

                let iface = self.ifaces.get(&ifid).unwrap();

                // (0) Check whether the received ip packet is addressed for the local machine
                let local_dest = /*ip.dest ==  Ipv6Addr::BROADCAST
                    || */iface
                        .addrs
                        .iter()
                        .any(|addr| addr.matches_ip(IpAddr::V6(ip.dest)));
                if !local_dest {
                    // (0) Check TTL
                    let mut pkt = ip.clone();
                    pkt.hop_limit = pkt.hop_limit.saturating_sub(1);

                    if pkt.hop_limit == 0 {
                        log::warn!(target: "inet/route", "dropping packet due to ttl");
                        return None;
                    }

                    // (2) Reroute packet.
                    match self.send_ip_packet(
                        SocketIfaceBinding::Any(self.ifaces.keys().copied().collect()),
                        IpPacket::V6(pkt),
                        true,
                    ) {
                        Ok(()) => return None,
                        Err(e) => panic!("not yet impl: forwarding without route: {}", e),
                    };
                }

                match ip.next_header {
                    0 => return Some(msg),
                    PROTO_UDP => {
                        let consumed = self.recv_udp_packet(IpPacketRef::V6(ip), ifid);
                        if consumed {
                            None
                        } else {
                            Some(msg)
                        }
                    }
                    PROTO_TCP => {
                        let consumed = self.capture_tcp_packet(IpPacketRef::V6(ip), todo!());
                        if consumed {
                            None
                        } else {
                            Some(msg)
                        }
                    }
                    k => panic!("internal error: unreachable code :: proto = {k}"),
                }
            }
            KIND_LINK_UPDATE => panic!("HUH"),
            _ => Some(msg),
        }
    }

    fn networking_layer_io_timeout(&mut self, msg: Message) -> Option<Message> {
        let Some(fd) = msg.try_content::<Fd>() else {
            return None;
        };

        let Some(socket) = self.sockets.get(fd) else {
            return None
        };

        match socket.typ {
            SocketType::SOCK_STREAM => {
                // TODO: If listeners have timesouts as well we must do something
                self.process_timeout(*fd, msg)
            }
            _ => {}
        }

        None
    }
}

impl UnwindSafe for IOContext {}
