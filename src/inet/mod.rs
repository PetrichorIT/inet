use crate::ip::{IpPacketRef, Ipv4Packet, Ipv6Packet, KIND_IPV4, KIND_IPV6};
use des::{
    prelude::{Message, MessageKind},
    runtime::random,
};
use std::{cell::RefCell, collections::HashMap, net::Ipv4Addr};

pub mod interface;
use interface::*;

pub mod socket;
use socket::*;

mod udp;
pub use udp::*;

pub mod tcp;
pub use tcp::socket::{TcpListener, TcpStream};

mod plugin;
pub use plugin::*;

thread_local! {
    static CURRENT: RefCell<Option<IOContext>> = const { RefCell::new(None) };
}

/// File descriptors.
pub type Fd = u32;

const KIND_IO_TIMEOUT: MessageKind = 0x0128;

pub struct IOContext {
    interfaces: HashMap<u64, Interface>,
    sockets: HashMap<Fd, Socket>,

    udp_manager: HashMap<Fd, UdpManager>,
    tcp_manager: HashMap<Fd, tcp::TcpController>,
    tcp_listeners: HashMap<Fd, tcp::socket::TcpListenerHandle>,

    fd: Fd,
    port: u16,
}

impl IOContext {
    pub fn empty() -> Self {
        Self {
            interfaces: HashMap::new(),
            sockets: HashMap::new(),

            udp_manager: HashMap::new(),
            tcp_manager: HashMap::new(),
            tcp_listeners: HashMap::new(),

            fd: 100,
            port: 1024,
        }
    }

    pub fn loopback_only() -> Self {
        let mut this = Self::empty();
        this.add_interface(Interface::loopback());
        this
    }

    pub fn eth_default(v4: Ipv4Addr) -> Self {
        let mut this = Self::empty();
        this.add_interface(Interface::loopback());
        this.add_interface(Interface::en0(random(), v4, NetworkDevice::eth_default()));
        this
    }

    pub fn set(self) {
        Self::swap_in(Some(self));
    }

    pub(self) fn swap_in(ingoing: Option<IOContext>) -> Option<IOContext> {
        CURRENT.with(|ctx| {
            let mut ctx = ctx.borrow_mut();
            let ret = ctx.take();
            *ctx = ingoing;
            ret
        })
    }

    pub(self) fn with_current<R>(f: impl FnOnce(&mut IOContext) -> R) -> R {
        CURRENT.with(|cell| {
            f(cell
                .borrow_mut()
                .as_mut()
                .expect("No IOContext set on the current module (missing IOPlugin)"))
        })
    }

    pub(self) fn try_with_current<R>(f: impl FnOnce(&mut IOContext) -> R) -> Option<R> {
        match CURRENT.try_with(|cell| Some(f(cell.borrow_mut().as_mut()?))) {
            Ok(v) => v,
            Err(_) => None,
        }
    }
}

impl IOContext {
    pub fn capture(&mut self, msg: Message) -> Option<Message> {
        let kind = msg.header().kind;
        match kind {
            KIND_IPV4 => {
                let Some(ip) = msg.try_content::<Ipv4Packet>() else {
                    log::error!("received eth-packet with kind=0x0800 (ip) but content was no ip-packet");
                    return Some(msg)
                };

                match ip.proto {
                    udp::PROTO_UDP => {
                        if self
                            .capture_udp_packet(IpPacketRef::V4(ip), msg.header().last_gate.clone())
                        {
                            None
                        } else {
                            Some(msg)
                        }
                    }
                    tcp::PROTO_TCP => {
                        if self
                            .capture_tcp_packet(IpPacketRef::V4(ip), msg.header().last_gate.clone())
                        {
                            None
                        } else {
                            Some(msg)
                        }
                    }
                    _ => Some(msg),
                }
            }
            KIND_IPV6 => {
                let Some(ip) = msg.try_content::<Ipv6Packet>() else {
                    log::error!("received eth-packet with kind=0x08DD (ip) but content was no ip-packet");
                    return Some(msg)
                };

                match ip.next_header {
                    udp::PROTO_UDP => {
                        if self
                            .capture_udp_packet(IpPacketRef::V6(ip), msg.header().last_gate.clone())
                        {
                            None
                        } else {
                            Some(msg)
                        }
                    }
                    tcp::PROTO_TCP => {
                        if self
                            .capture_tcp_packet(IpPacketRef::V6(ip), msg.header().last_gate.clone())
                        {
                            None
                        } else {
                            Some(msg)
                        }
                    }
                    _ => Some(msg),
                }
            }
            KIND_LINK_UNBUSY => self.capture_link_update(msg),
            KIND_IO_TIMEOUT => self.capture_io_timeout(msg),
            _ => {
                log::error!("Unkown packet {}", msg.str());
                None
            }
        }
    }

    fn capture_io_timeout(&mut self, msg: Message) -> Option<Message> {
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

    pub fn add_interface(&mut self, iface: Interface) {
        if self.interfaces.get(&iface.name.hash).is_some() {
            unimplemented!()
        } else {
            self.interfaces.insert(iface.name.hash, iface);
        }
    }

    pub fn get_interfaces(&self) -> Vec<Interface> {
        self.interfaces.values().cloned().collect::<Vec<_>>()
    }

    pub(self) fn create_fd(&mut self) -> Fd {
        loop {
            self.fd = self.fd.wrapping_add(1);
            if self.sockets.get(&self.fd).is_some() {
                continue;
            }
            return self.fd;
        }
    }
}
