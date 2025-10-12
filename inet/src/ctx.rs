use crate::{
    Udp,
    dns::{DnsResolver, default_dns_resolve},
    env::fs::Fs,
    extensions::Extensions,
    handle::{IOHandle, IOHandleWeak},
    interface::{ID_IPV6_TIMEOUT, IfId, InterfaceController, KIND_LINK_UPDATE},
    ipv4::Ipv4,
    ipv6::Ipv6,
    tcp::Tcp,
};
use des::prelude::{Header, Message, ModuleId};
use fxhash::{FxBuildHasher, FxHashMap};
use std::{
    fmt::Debug,
    io::Result,
    net::IpAddr,
    panic::UnwindSafe,
    sync::{Arc, Mutex, Weak},
};
use types::ip::{IpPacket, KIND_IPV4, KIND_IPV6};

use super::socket::*;
use types::{tcp::PROTO_TCP, udp::PROTO_UDP};

pub(crate) struct IOContext {
    // Link-Layer
    #[allow(unused)]
    pub(super) id: ModuleId,
    pub(super) ifaces: FxHashMap<IfId, InterfaceController>,

    // Networking Layer
    pub(super) ipv4: Ipv4,
    pub(super) ipv6: Ipv6,

    // Transport Layer
    pub(super) sockets: Sockets,
    pub(super) udp: Udp,
    pub(super) tcp: Tcp,

    // Application Layer
    pub(super) dns: DnsResolver,
    pub(super) fs: Fs,
    pub(super) extensions: Extensions,

    pub(super) current: Current,
    pub(super) meta_changed: bool,

    pub(super) handle: IOHandleWeak,
}

unsafe impl Send for IOContext {}

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

            ipv4: Ipv4::default(),
            ipv6: Ipv6::new(),

            dns: default_dns_resolve,
            sockets: Sockets::new(),
            udp: Udp::new(),
            tcp: Tcp::new(),

            fs: Fs::new(),

            extensions: Extensions::new(),
            current: Current { ifid: IfId::NULL },
            meta_changed: true,

            handle: Weak::new(),
        }
    }

    pub fn make(self) -> IOHandle {
        let handle = Arc::new(Mutex::new(self));
        let weak = Arc::downgrade(&handle);
        handle.lock().expect("illegal state").handle = weak;
        IOHandle(handle)
    }

    pub(super) fn handle(&self) -> IOHandle {
        IOHandle(self.handle.upgrade().expect("illegal state"))
    }

    // pub(super) fn is_current(&self) -> bool {
    //     let handle = self.handle();
    //     let current_handle = Self::try_current_handle();
    //     current_handle.is_some_and(|current_handle| Arc::ptr_eq(&current_handle.0, &handle.0))
    // }
}

impl IOContext {
    pub fn current_handle() -> IOHandle {
        IOHandle::current()
    }

    pub(super) fn with_current<R>(f: impl FnOnce(&mut IOContext) -> R) -> R {
        let handle = Self::current_handle();
        handle.do_io(f)
    }

    pub(super) fn failable_api<T>(f: impl FnOnce(&mut IOContext) -> Result<T>) -> Result<T> {
        let handle = Self::current_handle();
        handle.do_failable(f)
    }
}

pub struct PassThrough;

impl IOContext {
    pub fn recv(&mut self, msg: Message) -> Option<Message> {
        // Packets that are passed to the networking layer, are
        // not nessecarily addressed to any valid ip addr, but are valid for
        // the local MAC addr
        let l2 = self.recv_linklayer(msg);
        let (msg, ifid) = match l2 {
            LinkLayerResult::PassThrough(msg) => return Some(msg.with_extension(PassThrough)),
            LinkLayerResult::Consumed() => return None,
            LinkLayerResult::NetworkingPacket(msg, ifid) => (msg, ifid),
            LinkLayerResult::Timeout(timeout) => return self.networking_layer_io_timeout(timeout),
        };

        self.current.ifid = ifid;

        let l3 = self.recv_network_layer(msg, ifid);
        let (pkt, header) = match l3 {
            NetworkLayerResult::PassThrough(msg) => return Some(msg.with_extension(PassThrough)),
            NetworkLayerResult::Consumed() => return None,
            NetworkLayerResult::TransportLayerPacket(msg, header) => (msg, header),
        };

        let consumed = match pkt.tos() {
            PROTO_UDP => self.capture_udp_packet(pkt.as_ref(), ifid),
            PROTO_TCP => self.tcp_on_packet(pkt.as_ref(), ifid),
            proto => {
                let domain = if pkt.is_v4() {
                    SocketDomain::AF_INET
                } else {
                    SocketDomain::AF_INET6
                };
                if let Some(handle) = self.sockets.handlers.get(&(proto, domain)) {
                    let _ = handle.1.try_send((ifid, pkt));
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
        match msg.header.kind {
            KIND_IPV4 => self.ipv4_recv(msg, ifid),
            KIND_IPV6 => self.ipv6_recv(msg, ifid),
            KIND_LINK_UPDATE => panic!("should not happen"),
            _ => NetworkLayerResult::PassThrough(msg),
        }
    }

    pub fn event_end(&mut self) {
        self.ipv6.timer.schedule_wakeup();
        self.tcp_tick();
    }

    fn networking_layer_io_timeout(&mut self, msg: Message) -> Option<Message> {
        if msg.header.id == ID_IPV6_TIMEOUT {
            if let Err(e) = self.ipv6_handle_timer(msg) {
                tracing::error!("an error occured in the timer block: {e}");
            }
            return None;
        }

        let fd = *msg.body.try_content::<Fd>()?;

        // TCP2 grouped wakeup
        if fd == u32::MAX {
            self.tcp_timeout();
            return None;
        }

        None
    }

    pub fn get_path_mtu(&self, src: IpAddr, dst: IpAddr) -> usize {
        match (src, dst) {
            (IpAddr::V4(_), IpAddr::V4(dst)) => self.ipv4_get_local_mtu(dst),
            (IpAddr::V6(src), IpAddr::V6(dst)) => self.ipv6_get_path_mtu(src, dst),
            _ => panic!("unsupported address family"),
        }
    }

    pub fn send_ip_packet(&mut self, ifid: SocketIfaceBinding, pkt: IpPacket) -> Result<()> {
        match pkt {
            IpPacket::V4(pkt) => self.ipv4_send(ifid, pkt),
            IpPacket::V6(pkt) => self.ipv6_send(pkt, ifid.unwrap_ifid()),
        }
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
    TransportLayerPacket(IpPacket, Header),
    Consumed(),
}
