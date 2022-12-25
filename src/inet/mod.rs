use std::{cell::RefCell, collections::HashMap, net::Ipv4Addr};

mod interface;
use des::{prelude::Message, runtime::random};
pub use interface::*;

mod socket;
pub use socket::*;

mod udp;
pub use udp::*;

mod plugin;
pub use plugin::*;

use crate::ip::{IPPacket, KIND_IP};

thread_local! {
    static CURRENT: RefCell<Option<IOContext>> = const { RefCell::new(None) };
}

pub type Fd = u32;

pub struct IOContext {
    pub interfaces: HashMap<u64, Interface>,
    pub sockets: HashMap<u32, Socket>,

    udp_manager: HashMap<u32, UdpManager>,

    pub fd: Fd,
    pub port: u16,
}

impl IOContext {
    pub fn empty() -> Self {
        Self {
            interfaces: HashMap::new(),
            sockets: HashMap::new(),

            udp_manager: HashMap::new(),

            fd: 100,
            port: 1024,
        }
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

    pub fn swap_in(ingoing: Option<IOContext>) -> Option<IOContext> {
        CURRENT.with(|ctx| {
            let mut ctx = ctx.borrow_mut();
            let ret = ctx.take();
            *ctx = ingoing;
            ret
        })
    }

    pub fn with_current<R>(f: impl FnOnce(&mut IOContext) -> R) -> R {
        CURRENT.with(|cell| {
            f(cell
                .borrow_mut()
                .as_mut()
                .expect("No IOContext set on the current module (missing IOPlugin)"))
        })
    }

    pub fn try_with_current<R>(f: impl FnOnce(&mut IOContext) -> R) -> Option<R> {
        CURRENT.with(|cell| Some(f(cell.borrow_mut().as_mut()?)))
    }
}

impl IOContext {
    pub fn capture(&mut self, msg: Message) -> Option<Message> {
        let kind = msg.header().kind;
        if kind == KIND_IP {
            let Some(ip) = msg.try_content::<IPPacket>() else {
                log::error!("received eth-packet with kind=0x0800 (ip) but content was no ip-packet");
                return Some(msg)
            };

            match ip.proto {
                udp::PROTO_UDP => {
                    if self.capture_udp_packet(ip, msg.header().last_gate.clone()) {
                        None
                    } else {
                        Some(msg)
                    }
                }
                _ => Some(msg),
            }
        } else {
            None
        }
    }

    pub fn add_interface(&mut self, iface: Interface) {
        if self.interfaces.get(&iface.name.hash).is_some() {
            unimplemented!()
        } else {
            self.interfaces.insert(iface.name.hash, iface);
        }
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
