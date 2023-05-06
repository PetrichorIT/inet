use crate::{
    arp::ArpTable,
    icmp::Icmp,
    interface::{IfId, Interface, LinkLayerResult, KIND_LINK_UPDATE},
    pcap::Pcap,
    routing::{Ipv4RoutingTable, Ipv6RoutingTable},
    uds, IOPlugin,
};
use des::{net::plugin::PluginError, prelude::Message};
use fxhash::{FxBuildHasher, FxHashMap};
use inet_types::{
    icmp::PROTO_ICMP,
    ip::{IpPacket, IpPacketRef, Ipv4Packet, Ipv6Packet, KIND_IPV4, KIND_IPV6},
};
use std::{
    cell::RefCell,
    net::{IpAddr, Ipv4Addr},
    panic::UnwindSafe,
};

use super::{socket::*, tcp::Tcp, udp::UdpControlBlock};
use inet_types::{tcp::PROTO_TCP, udp::PROTO_UDP};

thread_local! {
    static CURRENT: RefCell<Option<IOContext>> = const { RefCell::new(None) };
}

pub struct IOContext {
    pub(super) ifaces: FxHashMap<IfId, Interface>,

    pub(super) arp: ArpTable,
    pub(super) ipv4router: Ipv4RoutingTable,
    pub(super) ipv6router: Ipv6RoutingTable,

    pub(super) pcap: RefCell<Pcap>,
    pub(super) icmp: Icmp,

    pub(super) sockets: FxHashMap<Fd, Socket>,
    pub(super) udp_manager: FxHashMap<Fd, UdpControlBlock>,
    pub(super) tcp: Tcp,
    pub(super) uds_dgrams: FxHashMap<Fd, uds::UnixDatagramHandle>,
    pub(super) uds_listeners: FxHashMap<Fd, uds::UnixListenerHandle>,

    pub(super) fd: Fd,
    pub(super) port: u16,
}

impl IOContext {
    pub fn empty() -> Self {
        Self {
            ifaces: FxHashMap::with_hasher(FxBuildHasher::default()),

            arp: ArpTable::new(),
            ipv4router: Ipv4RoutingTable::new(),
            ipv6router: Ipv6RoutingTable::new(),

            pcap: RefCell::new(Pcap::new()),
            icmp: Icmp::new(),

            sockets: FxHashMap::with_hasher(FxBuildHasher::default()),
            udp_manager: FxHashMap::with_hasher(FxBuildHasher::default()),
            tcp: Tcp::new(),
            uds_dgrams: FxHashMap::with_hasher(FxBuildHasher::default()),
            uds_listeners: FxHashMap::with_hasher(FxBuildHasher::default()),

            fd: 100,
            port: 1024,
        }
    }

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
                        self.icmp_ttl_expired(ifid, ip);
                        return None;
                    }

                    // (2) Reroute packet.
                    match self.send_ip_packet(
                        SocketIfaceBinding::Any(self.ifaces.keys().copied().collect()),
                        IpPacket::V4(pkt),
                        true,
                    ) {
                        Ok(()) => return None,
                        Err(e) => {
                            log::error!(target: "inet/route", "Failed to forward packet due to internal err: {e}");
                            self.icmp_routing_failed(e, ip);
                            // Maybe return dropped packet ?
                            return None;
                        }
                    };
                }

                match ip.proto {
                    0 => return Some(msg),
                    PROTO_ICMP => {
                        let consumed = self.recv_icmpv4_packet(ip, ifid);
                        if consumed {
                            None
                        } else {
                            Some(msg)
                        }
                    }
                    PROTO_UDP => {
                        let consumed = self.recv_udp_packet(IpPacketRef::V4(ip), ifid);
                        if consumed {
                            None
                        } else {
                            Some(msg)
                        }
                    }
                    PROTO_TCP => {
                        let consumed = self.capture_tcp_packet(IpPacketRef::V4(ip), ifid);
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
                        let consumed = self.capture_tcp_packet(IpPacketRef::V6(ip), ifid);
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

        if socket.typ == SocketType::SOCK_STREAM {
            // TODO: If listeners have timesouts as well we must do something
            self.process_timeout(*fd, msg)
        }

        None
    }
}

impl UnwindSafe for IOContext {}
