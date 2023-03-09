use des::net::plugin::Plugin;
use des::prelude::*;

use crate::{
    ip::{Ipv4Packet, Ipv6Packet, KIND_IPV4, KIND_IPV6},
    FromBytestream,
};

use super::{TcpPacket, PROTO_TCP};

/// A logger for TCP packet.
pub struct TcpDebugPlugin;

impl TcpDebugPlugin {
    fn log(&self, src: IpAddr, dest: IpAddr, tcp: TcpPacket) {
        log::warn!(
            "> {} --> {} [ {} seq: {} ack: {} win: {} content: {} bytes]",
            SocketAddr::new(src, tcp.src_port),
            SocketAddr::new(dest, tcp.dest_port),
            tcp.flags,
            tcp.seq_no,
            tcp.ack_no,
            tcp.window,
            tcp.content.len(),
        )
    }
}

impl Plugin for TcpDebugPlugin {
    fn capture_incoming(&mut self, msg: Message) -> Option<Message> {
        if msg.header().kind == KIND_IPV4 {
            let ip = msg.content::<Ipv4Packet>();
            if ip.proto == PROTO_TCP {
                let tcp = TcpPacket::from_buffer(&ip.content).unwrap();
                self.log(IpAddr::V4(ip.src), IpAddr::V4(ip.dest), tcp);
            }
        }
        if msg.header().kind == KIND_IPV6 {
            let ip = msg.content::<Ipv6Packet>();
            if ip.next_header == PROTO_TCP {
                let tcp = TcpPacket::from_buffer(&ip.content).unwrap();
                self.log(IpAddr::V6(ip.src), IpAddr::V6(ip.dest), tcp)
            }
        }

        Some(msg)
    }
}
