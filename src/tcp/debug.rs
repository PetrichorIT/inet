use des::prelude::*;

use crate::{
    interface::KIND_LINK_UNBUSY,
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
    fn capture(&mut self, msg: Option<Message>) -> Option<Message> {
        if let Some(ref msg) = msg {
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
            // if msg.header().kind == KIND_LINK_UNBUSY {
            //     log::debug!("! [0x{:x}] link unbusy", msg.content::<u64>())
            // }
        }
        msg
    }
    fn defer(&mut self) {}
}
