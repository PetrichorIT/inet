use crate::{ip::IpPacket, IOContext};
use std::io;

pub fn send_ip(pkt: IpPacket) -> io::Result<()> {
    IOContext::with_current(|ctx| {
        let ifid = *ctx.interfaces2.iter().next().unwrap().0;
        ctx.send_ip_packet(ifid, pkt)
    })
}
