use crate::{socket::SocketIfaceBinding, IOContext};
use inet_types::ip::IpPacket;
use std::io;

pub fn send_ip(pkt: IpPacket) -> io::Result<()> {
    IOContext::with_current(|ctx| {
        let ifid = *ctx.ifaces.iter().next().unwrap().0;
        ctx.send_ip_packet(SocketIfaceBinding::Bound(ifid), pkt, true)
    })
}
