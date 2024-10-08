use crate::{
    arp::ArpTable,
    dns::{default_dns_resolve, DnsResolver},
    extensions::Extensions,
    fs::Fs,
    icmp::Icmp,
    interface::{IfId, Interface, LinkLayerResult, ID_IPV6_TIMEOUT, KIND_LINK_UPDATE},
    ipv6::Ipv6,
    routing::{FwdV4, Ipv6RoutingTable},
    tcp2::{self, PROTO_TCP2},
    Udp,
};
use des::{
    net::module::current,
    prelude::{Message, ModuleId},
};
use fxhash::{FxBuildHasher, FxHashMap};
use std::{
    cell::RefCell,
    io::{Error, ErrorKind, Result},
    net::{IpAddr, Ipv4Addr},
    panic::UnwindSafe,
};
use types::{
    icmpv4::PROTO_ICMPV4,
    icmpv6::PROTO_ICMPV6,
    ip::{IpPacket, IpPacketRef, Ipv4Packet, Ipv6Packet, KIND_IPV4, KIND_IPV6},
};

#[cfg(feature = "uds")]
use crate::uds::Uds;

use super::{socket::*, tcp::Tcp};
use types::{tcp::PROTO_TCP, udp::PROTO_UDP};

thread_local! {
    static CURRENT: RefCell<Option<Box<IOContext>>> = const { RefCell::new(None) };
}

pub(crate) struct IOContext {
    #[allow(unused)]
    pub(super) id: ModuleId,
    pub(super) ifaces: FxHashMap<IfId, Interface>,

    pub(super) ipv6: Ipv6,

    pub(super) arp: ArpTable,
    pub(super) ipv4_fwd: FwdV4,
    pub(super) ipv6router: Ipv6RoutingTable,
    pub(super) icmp: Icmp,

    pub(super) dns: DnsResolver,

    pub(super) sockets: Sockets,
    pub(super) udp: Udp,
    pub(super) tcp: Tcp,
    pub(super) tcp2: tcp2::Tcp,

    #[cfg(feature = "uds")]
    pub(super) uds: Uds,

    pub(super) fs: Fs,

    pub(super) fd: Fd,
    pub(super) port: u16,

    pub(super) extensions: Extensions,

    pub(super) current: Current,
    pub(super) meta_changed: bool,
}

#[derive(Debug, Default, Clone)]
pub struct IOMeta {
    pub ip: Option<IpAddr>,
}

#[derive(Debug, Clone)]
pub struct Current {
    pub ifid: IfId,
}

impl Current {
    pub fn fetch() -> Current {
        IOContext::with_current(|ctx| ctx.current.clone())
    }
}

impl IOContext {
    pub fn new(id: ModuleId) -> Self {
        Self {
            id,
            ifaces: FxHashMap::with_hasher(FxBuildHasher::default()),
            ipv6: Ipv6::new(),

            arp: ArpTable::new(),
            ipv4_fwd: FwdV4::new(),
            ipv6router: Ipv6RoutingTable::new(),
            icmp: Icmp::new(),

            dns: default_dns_resolve,

            sockets: Sockets::new(),
            udp: Udp::new(),
            tcp: Tcp::new(),
            tcp2: tcp2::Tcp::new(),

            #[cfg(feature = "uds")]
            uds: Uds::new(),
            fs: Fs::new(),

            extensions: Extensions::new(),

            fd: 100,
            port: 1024,

            current: Current { ifid: IfId::NULL },
            meta_changed: true,
        }
    }

    pub(super) fn swap_in(ingoing: Option<Box<IOContext>>) -> Option<Box<IOContext>> {
        CURRENT.with(|ctx| {
            let mut ctx = ctx.borrow_mut();
            let ret = ctx.take();
            *ctx = ingoing;
            ret
        })
    }

    pub(super) fn with_current<R>(f: impl FnOnce(&mut IOContext) -> R) -> R {
        CURRENT.with(|cell| {
            f(cell
                .borrow_mut()
                .as_mut()
                .unwrap_or_else(|| panic!("Missing IOContext")))
        })
    }

    pub(super) fn failable_api<T>(f: impl FnOnce(&mut IOContext) -> Result<T>) -> Result<T> {
        CURRENT.with(|cell| {
            let mut ctx = cell.borrow_mut();
            let Some(ctx) = ctx.as_mut() else {
                return Err(Error::new(ErrorKind::Other, "Missing IOContext"));
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
    pub fn meta(&self) -> IOMeta {
        IOMeta { ip: self.get_ip() }
    }

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

        self.current.ifid = ifid.clone();

        let kind = msg.header().kind;
        match kind {
            KIND_IPV4 => {
                let Some(ip) = msg.try_content::<Ipv4Packet>() else {
                    tracing::error!(
                        "received eth-packet with kind=0x0800 (ip) but content was no ipv4-packet"
                    );
                    return Some(msg);
                };

                let iface = self.ifaces.get(&ifid).unwrap();

                // (0) Check whether the received ip packet is addressed for the local machine
                let local_dest = ip.dst == Ipv4Addr::BROADCAST || iface.addrs.v4.matches(ip.dst);
                // .iter()
                // .any(|addr| addr.matches(IpAddr::V4(ip.dest)));

                if !local_dest {
                    // (0) Check TTL
                    let mut pkt = ip.clone();
                    pkt.ttl = pkt.ttl.saturating_sub(1);

                    if pkt.ttl == 0 {
                        tracing::warn!("dropping packet due to ttl");
                        self.icmp_ttl_expired(ifid, ip);
                        return None;
                    }

                    // (2) Reroute packet.
                    match self.send_ip_packet(
                        SocketIfaceBinding::Any(self.ifaces.keys().cloned().collect()),
                        IpPacket::V4(pkt),
                        true,
                    ) {
                        Ok(()) => return None,
                        Err(e) => {
                            tracing::error!("Failed to forward packet due to internal err: {e}");
                            self.icmp_routing_failed(e, ip);
                            // Maybe return dropped packet ?
                            return None;
                        }
                    };
                }

                match ip.proto {
                    0 => Some(msg),
                    PROTO_ICMPV4 => {
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
                    PROTO_TCP2 => {
                        let consumed = self.tcp2_on_packet(IpPacketRef::V4(ip), ifid);
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
                    tracing::error!(
                        "received eth-packet with kind=0x0800 (ip) but content was no ipv4-packet"
                    );
                    return Some(msg);
                };

                let iface = self.get_iface(ifid).unwrap();

                // (0) Check whether the received ip packet is addressed for the local machine
                let local_dest = iface.addrs.v6.matches(ip.dst);

                let multicast = ip.dst.is_multicast();

                if !local_dest && !multicast {
                    // (0) Check TTL
                    let mut pkt = ip.clone();
                    pkt.hop_limit = pkt.hop_limit.saturating_sub(1);

                    if pkt.hop_limit == 0 {
                        tracing::warn!("dropping packet due to ttl");
                        self.ipv6_icmp_send_ttl_expired(&pkt, ifid).unwrap();
                        return None;
                    }

                    // (2) Reroute packet.
                    match self.send_ip_packet(
                        SocketIfaceBinding::Any(self.ifaces.keys().cloned().collect()),
                        IpPacket::V6(pkt),
                        true,
                    ) {
                        Ok(()) => return None,
                        Err(e) => {
                            panic!(
                                "{}: not yet impl: forwarding without route: {}",
                                current().path(),
                                e
                            )
                        }
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
                    PROTO_ICMPV6 => {
                        let consumed = self.ipv6_icmp_recv(ip, ifid).unwrap();
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

    pub fn event_end(&mut self) {
        self.ipv6.timer.schedule_wakeup();
    }

    fn networking_layer_io_timeout(&mut self, msg: Message) -> Option<Message> {
        if msg.header().id == ID_IPV6_TIMEOUT {
            if let Err(e) = self.ipv6_handle_timer(msg) {
                tracing::error!("an error occured in the timer block: {e}");
            }
            return None;
        }

        let Some(fd) = msg.try_content::<Fd>() else {
            return None;
        };

        let Some(socket) = self.sockets.get(fd) else {
            return None;
        };

        if socket.typ == SocketType::SOCK_STREAM {
            // TODO: If listeners have timesouts as well we must do something
            self.tcp_timeout(*fd, msg)
        }

        None
    }
}

impl UnwindSafe for IOContext {}

impl Drop for IOContext {
    fn drop(&mut self) {
        #[cfg(feature = "libpcap")]
        crate::libpcap::close(self.id);
    }
}
