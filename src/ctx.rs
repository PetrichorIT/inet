use crate::{
    arp::ArpTable,
    icmp::Icmp,
    interface::{IfId, Interface, LinkLayerResult, KIND_LINK_UPDATE},
    pcap::Pcap,
    routing::{ForwardingTableV4, Ipv6RoutingTable},
    uds::Uds,
    IOPlugin, Udp,
};
use des::{net::plugin::PluginError, prelude::Message};
use fxhash::{FxBuildHasher, FxHashMap};
use inet_types::{
    icmp::PROTO_ICMP,
    ip::{IpPacket, IpPacketRef, Ipv4Packet, Ipv6Packet, KIND_IPV4, KIND_IPV6},
};
use std::{
    cell::RefCell,
    io::{Error, ErrorKind, Result},
    net::{IpAddr, Ipv4Addr},
    panic::UnwindSafe,
};

use super::{socket::*, tcp::Tcp};
use inet_types::{tcp::PROTO_TCP, udp::PROTO_UDP};

thread_local! {
    static CURRENT: RefCell<Option<IOContext>> = const { RefCell::new(None) };
}

pub(crate) struct IOContext {
    pub(super) ifaces: FxHashMap<IfId, Interface>,

    pub(super) arp: ArpTable,
    pub(super) ipv4_fwd: ForwardingTableV4,
    pub(super) ipv6router: Ipv6RoutingTable,

    pub(super) pcap: RefCell<Pcap>,
    pub(super) icmp: Icmp,

    pub(super) sockets: Sockets,
    pub(super) udp: Udp,
    pub(super) tcp: Tcp,
    pub(super) uds: Uds,

    pub(super) fd: Fd,
    pub(super) port: u16,

    pub(super) current: Current,
}

#[derive(Debug, Clone)]
pub(crate) struct Current {
    pub ifid: IfId,
}

impl IOContext {
    pub fn empty() -> Self {
        Self {
            ifaces: FxHashMap::with_hasher(FxBuildHasher::default()),

            arp: ArpTable::new(),
            ipv4_fwd: ForwardingTableV4::new(),
            ipv6router: Ipv6RoutingTable::new(),

            pcap: RefCell::new(Pcap::new()),
            icmp: Icmp::new(),

            sockets: Sockets::new(),
            udp: Udp::new(),
            tcp: Tcp::new(),
            uds: Uds::new(),

            fd: 100,
            port: 1024,

            current: Current { ifid: IfId::NULL },
        }
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

    pub(super) fn failable_api<T>(f: impl FnOnce(&mut IOContext) -> Result<T>) -> Result<T> {
        CURRENT.with(|cell| {
            let mut ctx = cell.borrow_mut();
            let Some(ctx) = ctx.as_mut() else {
                let error = PluginError::expected::<IOPlugin>();
                return Err(Error::new(ErrorKind::Other, error))
            };
            f(ctx)
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
        let (msg, ifid) = match l2 {
            PassThrough(msg) => return Some(msg),
            Consumed() => return None,
            NetworkingPacket(msg, ifid) => (msg, ifid),
            Timeout(timeout) => return self.networking_layer_io_timeout(timeout),
        };

        self.current.ifid = ifid;

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
                    k => {
                        if let Some(handle) = self.sockets.handlers.get(&(k, SocketDomain::AF_INET))
                        {
                            let _ = handle.1.try_send(IpPacket::V4(ip.clone()));
                            return None;
                        }
                        panic!("internal error: unreachable code :: proto = {k}");
                    }
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
                    k => {
                        if let Some(handle) =
                            self.sockets.handlers.get(&(k, SocketDomain::AF_INET6))
                        {
                            let _ = handle.1.try_send(IpPacket::V6(ip.clone()));
                            return None;
                        }
                        panic!("internal error: unreachable code :: proto = {k}");
                    }
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
