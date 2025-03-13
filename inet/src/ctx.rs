use crate::{
    arp::ArpTable,
    dns::{default_dns_resolve, DnsResolver},
    extensions::Extensions,
    fs::Fs,
    icmp::Icmp,
    interface::{IfId, InterfaceController, ID_IPV6_TIMEOUT, KIND_LINK_UPDATE},
    ipv6::Ipv6,
    routing::{FwdV4, Ipv6RoutingTable},
    tcp2::{self, PROTO_TCP2},
    Udp,
};
use des::{
    net::module::{current, try_current},
    prelude::{Message, MessageHeader, ModuleId},
};
use fxhash::{FxBuildHasher, FxHashMap};
use std::{
    cell::RefCell,
    io::{Error, ErrorKind, Result},
    net::IpAddr,
    panic::UnwindSafe,
};
use types::{
    icmpv4::PROTO_ICMPV4,
    icmpv6::PROTO_ICMPV6,
    ip::{IpPacket, Ipv4Packet, Ipv6Packet, KIND_IPV4, KIND_IPV6},
};

use super::{socket::*, tcp::Tcp};
use types::{tcp::PROTO_TCP, udp::PROTO_UDP};

thread_local! {
    static CURRENT: RefCell<Option<Box<IOContext>>> = const { RefCell::new(None) };
}

pub(crate) struct IOContext {
    #[allow(unused)]
    pub(super) id: ModuleId,
    pub(super) ifaces: FxHashMap<IfId, InterfaceController>,

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
            *ctx = ingoing.map(|mut ctx| {
                ctx.id = current().id();
                ctx
            });
            ret
        })
    }

    pub(super) fn with_current<R>(f: impl FnOnce(&mut IOContext) -> R) -> R {
        CURRENT.with(|cell| {
            let mut brw = cell.borrow_mut();
            f(brw.as_mut().unwrap_or_else(|| panic!("Missing IOContext")))
        })
    }

    pub(super) fn failable_api<T>(f: impl FnOnce(&mut IOContext) -> Result<T>) -> Result<T> {
        CURRENT.with(|cell| {
            let mut ctx = cell.borrow_mut();
            let Some(ctx) = ctx.as_mut() else {
                return Err(Error::new(ErrorKind::Other, "Missing IOContext"));
            };
            if try_current().map_or(false, |m| m.id() != ctx.id) {
                return Err(Error::new(ErrorKind::Other, "Drop chain"));
            }
            f(ctx)
        })
    }

    pub(super) fn try_with_current<R>(f: impl FnOnce(&mut IOContext) -> R) -> Option<R> {
        CURRENT
            .try_with(|cell| {
                let mut brw = cell.try_borrow_mut().expect("BorrowMut at IOContext");
                brw.as_mut()
                    .map(|brw| {
                        if try_current().map_or(false, |m| m.id() == brw.id) {
                            Some(f(brw))
                        } else {
                            None
                        }
                    })
                    .flatten()
            })
            .ok()
            .flatten()
    }
}

impl IOContext {
    pub fn meta(&self) -> IOMeta {
        IOMeta { ip: self.get_ip() }
    }

    pub fn recv(&mut self, msg: Message) -> Option<Message> {
        // Packets that are passed to the networking layer, are
        // not nessecarily addressed to any valid ip addr, but are valid for
        // the local MAC addr
        let l2 = self.recv_linklayer(msg);
        let (msg, ifid) = match l2 {
            LinkLayerResult::PassThrough(msg) => return Some(msg),
            LinkLayerResult::Consumed() => return None,
            LinkLayerResult::NetworkingPacket(msg, ifid) => (msg, ifid),
            LinkLayerResult::Timeout(timeout) => return self.networking_layer_io_timeout(timeout),
        };

        self.current.ifid = ifid.clone();

        tracing::info!(
            "{ifid}: {} / {}",
            msg.str(),
            msg.try_content::<Ipv6Packet>().unwrap().dst
        );

        let l3 = self.recv_network_layer(msg, ifid);
        let (pkt, header) = match l3 {
            NetworkLayerResult::PassThrough(msg) => return Some(msg),
            NetworkLayerResult::Consumed() => return None,
            NetworkLayerResult::TransportLayerPacket(msg, header) => (msg, header),
        };

        let consumed = match pkt.tos() {
            PROTO_UDP => self.capture_udp_packet(pkt.as_ref(), ifid),
            PROTO_TCP => self.capture_tcp_packet(pkt.as_ref(), ifid),
            PROTO_TCP2 => self.tcp2_on_packet(pkt.as_ref(), ifid),
            proto => {
                let domain = pkt
                    .is_v4()
                    .then_some(SocketDomain::AF_INET)
                    .unwrap_or(SocketDomain::AF_INET6);
                if let Some(handle) = self.sockets.handlers.get(&(proto, domain)) {
                    let _ = handle.1.try_send(pkt);
                    return None;
                }
                panic!("internal error: unreachable code :: proto = {proto}");
            }
        };

        (!consumed).then(|| match pkt {
            IpPacket::V4(v4) => Message::from_parts(header, Some(v4)),
            IpPacket::V6(v6) => Message::from_parts(header, Some(v6)),
        })
    }

    pub fn recv_network_layer(&mut self, msg: Message, ifid: IfId) -> NetworkLayerResult {
        match msg.header().kind {
            KIND_IPV4 => self.ipv4_recv(msg, ifid),
            KIND_IPV6 => self.ipv6_recv(msg, ifid),
            KIND_LINK_UPDATE => panic!("should not happen"),
            _ => NetworkLayerResult::PassThrough(msg),
        }
    }

    fn ipv4_recv(&mut self, msg: Message, ifid: IfId) -> NetworkLayerResult {
        let Ok((pkt, header)) = msg.try_cast::<Ipv4Packet>() else {
            tracing::error!(
                "received eth-packet with kind=0x0800 (ip) but content was no ipv4-packet"
            );
            return NetworkLayerResult::Consumed();
        };

        let iface = self
            .ifaces
            .get(&ifid)
            .expect("interface was already resolved");

        let is_local_dest = iface.bindings.v4.matches(pkt.dst) || pkt.dst.is_broadcast();
        if !is_local_dest {
            let mut pkt = pkt;
            pkt.ttl = pkt.ttl.saturating_sub(1);

            if pkt.ttl == 0 {
                tracing::warn!("dropped ipv4-packet with ttl 0");
                self.icmp_ttl_expired(ifid, &pkt);
                return NetworkLayerResult::Consumed();
            }

            tracing::debug!("fwd packet to {}", pkt.dst);

            if let Err(error) = self.send_ip_packet(
                SocketIfaceBinding::Any(self.ifaces.keys().cloned().collect()),
                IpPacket::V4(pkt.clone()), // TODO: to not copy, use a result Err(Packet)
                true,
            ) {
                tracing::error!("failed to forward ip-packet {error}");
                self.icmp_routing_failed(error, &pkt);
            }

            return NetworkLayerResult::Consumed();
        }

        match pkt.proto {
            PROTO_ICMPV4 => {
                let _consumed = self.recv_icmpv4_packet(&pkt, ifid);
                NetworkLayerResult::Consumed()
            }
            0 => NetworkLayerResult::PassThrough(Message::from_parts(header, Some(pkt))),
            _ => NetworkLayerResult::TransportLayerPacket(IpPacket::V4(pkt), header),
        }
    }

    fn ipv6_recv(&mut self, msg: Message, ifid: IfId) -> NetworkLayerResult {
        let Ok((pkt, header)) = msg.try_cast::<Ipv6Packet>() else {
            tracing::error!(
                "received eth-packet with kind=0x86DD (ip) but content was no ipv6-packet"
            );
            return NetworkLayerResult::Consumed();
        };

        let iface = self
            .ifaces
            .get(&ifid)
            .expect("interface was already resolved");

        let is_local_dest = iface.bindings.v6.matches(pkt.dst) || pkt.dst.is_multicast();
        if !is_local_dest {
            let mut pkt = pkt;
            pkt.hop_limit = pkt.hop_limit.saturating_sub(1);

            if pkt.hop_limit == 0 {
                tracing::warn!("dropped ipv6-packet with ttl 0");
                self.ipv6_icmp_send_ttl_expired(&pkt, ifid)
                    .expect("ttl expired failed");
                return NetworkLayerResult::Consumed();
            }

            if let Err(error) = self.send_ip_packet(
                SocketIfaceBinding::Any(self.ifaces.keys().cloned().collect()),
                IpPacket::V6(pkt.clone()), // TODO: to not copy, use a result Err(Packet)
                true,
            ) {
                tracing::error!("failed to forward ip-packet {error}");
                panic!("TODO: cannot send ipv6 packet")
            }

            return NetworkLayerResult::Consumed();
        }

        match pkt.next_header {
            PROTO_ICMPV6 => {
                let _consumed = self.ipv6_icmp_recv(&pkt, ifid);
                NetworkLayerResult::Consumed()
            }
            0 => NetworkLayerResult::PassThrough(Message::from_parts(header, Some(pkt))),
            _ => NetworkLayerResult::TransportLayerPacket(IpPacket::V6(pkt), header),
        }
    }

    pub fn event_end(&mut self) {
        self.ipv6.timer.schedule_wakeup();
        self.tcp2_tick();
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
        let fd = *fd;

        // TCP2 grouped wakeup
        if fd == u32::MAX {
            self.tcp2_timeout();
            return None;
        }

        let Some(socket) = self.sockets.get(&fd) else {
            return None;
        };

        if socket.typ == SocketType::SOCK_STREAM {
            // TODO: If listeners have timesouts as well we must do something
            self.tcp_timeout(fd, msg);
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

#[derive(Debug)]
pub enum LinkLayerResult {
    PassThrough(Message),
    Consumed(),
    NetworkingPacket(Message, IfId),
    Timeout(Message),
}

#[derive(Debug)]
pub enum NetworkLayerResult {
    PassThrough(Message),
    TransportLayerPacket(IpPacket, MessageHeader),
    Consumed(),
}
