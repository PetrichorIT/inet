use std::{collections::VecDeque, task::Waker};

use fxhash::FxHashMap;
use types::{
    ip::{IpPacket, Ipv4Flags, Ipv4Packet, Ipv6Packet},
    tcp::TcpPacket,
};

use crate::{socket::Fd, tcp2::PROTO_TCP2};
use bytepack::ToBytestream;

use super::Connection;

#[derive(Debug, Clone, Default)]
pub struct TcpSenderBuffer {
    pub pending: FxHashMap<Fd, VecDeque<TcpPacket>>,
    pub has_unresolved_wakeups: bool,
}

#[derive(Debug)]
pub struct TcpSender<'a> {
    pub buffer: &'a mut VecDeque<TcpPacket>,
    pub unresolved_wakeups: &'a mut bool,
}

impl TcpSenderBuffer {
    pub fn sender<'a>(&'a mut self, fd: Fd) -> TcpSender<'a> {
        TcpSender {
            buffer: self.pending.entry(fd).or_insert(VecDeque::new()),
            unresolved_wakeups: &mut self.has_unresolved_wakeups,
        }
    }
}

impl TcpSender<'_> {
    pub fn send(&mut self, pkt: TcpPacket) {
        self.buffer.push_back(pkt);
    }

    pub fn wake(&mut self, wakers: &mut Vec<Waker>) {
        wakers.drain(..).for_each(|waker| {
            *self.unresolved_wakeups = true;
            waker.wake();
        });
    }

    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    pub fn next(&mut self, con: &Connection) -> Option<IpPacket> {
        let pkt = self.buffer.pop_front()?;

        use std::net::IpAddr::*;
        match (con.quad.src.ip(), con.quad.dst.ip()) {
            (V4(src), V4(dst)) => Some(IpPacket::V4(Ipv4Packet {
                dscp: 0,
                enc: 0,
                identification: 0,
                flags: Ipv4Flags {
                    df: false,
                    mf: false,
                },
                fragment_offset: 0,
                ttl: con.cfg.ttl,
                proto: PROTO_TCP2,
                src,
                dst,
                content: pkt.to_vec().expect("failed to encode"),
            })),
            (V6(src), V6(dst)) => Some(IpPacket::V6(Ipv6Packet {
                traffic_class: 0,
                flow_label: 0,
                next_header: PROTO_TCP2,
                hop_limit: con.cfg.ttl,
                src,
                dst,
                content: pkt.to_vec().expect("failed to encodes"),
            })),
            _ => todo!(),
        }
    }
}
