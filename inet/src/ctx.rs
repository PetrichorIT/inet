use des::{
    ObjectPath,
    prelude::{Header, Message},
};
use std::{
    fmt::Debug,
    net::IpAddr,
    panic::UnwindSafe,
    sync::{Arc, Mutex, Weak},
};

use crate::{
    Udp,
    dns::{DnsResolver, default_dns_resolve},
    env::fs::Fs,
    extensions::Extensions,
    handle::{IOHandle, IOHandleWeak},
    interface::{ID_IPV6_TIMEOUT, IfId, Interfaces, KIND_LINK_UPDATE},
    ioctx,
    ipv4::Ipv4,
    ipv6::Ipv6,
    socket::{Fd, Sockets},
    tcp::Tcp,
};

use types::{
    arp::KIND_ARP,
    ip::{IpPacket, IpPacketRef, KIND_IPV4, KIND_IPV6},
    tcp::PROTO_TCP,
    udp::PROTO_UDP,
};

pub(crate) struct IOContext {
    // Link-Layer
    pub(super) path: ObjectPath,
    pub(super) ifaces: Interfaces,

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
        ioctx().do_mutating(|ctx| ctx.current.clone())
    }
}

impl IOContext {
    pub fn new(id: ObjectPath) -> Self {
        Self {
            path: id,
            ifaces: Interfaces::default(),

            ipv4: Ipv4::default(),
            ipv6: Ipv6::default(),

            dns: default_dns_resolve,
            sockets: Sockets::default(),
            udp: Udp::default(),
            tcp: Tcp::default(),

            fs: Fs::default(),

            extensions: Extensions::default(),
            current: Current {
                ifid: IfId::UNKNOWN,
            },
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
}

pub struct PassThrough;

impl IOContext {
    pub fn recv(&mut self, msg: Message) -> Option<Message> {
        // Packets that are passed to the networking layer, are
        // not nessecarily addressed to any valid ip addr, but are valid for
        // the local MAC addr
        let l1 = self.recv_physlayer(msg);
        let msg = match l1 {
            LayerResult::PassThrough(msg) => {
                return Some(msg.with_extension(PassThrough));
            }
            LayerResult::Consumed => return None,
            LayerResult::Forward(msg) => msg,
        };

        let l2 = self.recv_linklayer(msg);
        let (msg, ifid) = match l2 {
            LinkLayerResult::PassThrough(msg) => {
                return Some(msg.with_extension(PassThrough));
            }
            LinkLayerResult::Consumed => return None,
            LinkLayerResult::Forward((msg, ifid)) => (msg, ifid),
        };

        self.current.ifid = ifid;

        let l3 = self.recv_network_layer(msg, ifid);
        let (pkt, header) = match l3 {
            NetworkLayerResult::PassThrough(msg) => {
                return Some(msg.with_extension(PassThrough));
            }
            NetworkLayerResult::Consumed => return None,
            NetworkLayerResult::Forward((msg, header)) => (msg, header),
        };

        let consumed = match pkt.proto() {
            PROTO_UDP => self.udp_on_packet(pkt.as_ref(), ifid),
            PROTO_TCP => self.tcp_on_packet(pkt.as_ref(), ifid),
            _ => {
                // Transport layer packets that directed at valid addrs are allways consumed
                true
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

    pub fn general_io_timeout(&mut self, msg: Message) -> Option<Message> {
        if msg.header.id == KIND_ARP {
            self.recv_arp_wakeup();
            return None;
        }

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

    pub fn icmp_port_unreachable(&mut self, interface: IfId, pkt: IpPacketRef) {
        match pkt {
            IpPacketRef::V4(pkt) => self.ipv4_icmp_port_unreachable(interface, pkt),
            IpPacketRef::V6(pkt) => self
                .ipv6_icmp_send_port_unreachable(interface, pkt)
                .expect("no fail"),
        }
    }
}

impl UnwindSafe for IOContext {}

impl Drop for IOContext {
    fn drop(&mut self) {
        #[cfg(feature = "libpcap")]
        crate::libpcap::close(self.path.clone());
    }
}

#[derive(Debug, Clone)]
pub enum LayerResult<T> {
    PassThrough(Message),
    Consumed,
    Forward(T),
}

pub type PhysLayerResult = LayerResult<Message>;
pub type LinkLayerResult = LayerResult<(Message, IfId)>;
pub type NetworkLayerResult = LayerResult<(IpPacket, Header)>;
