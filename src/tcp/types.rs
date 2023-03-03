use std::net::{IpAddr, SocketAddr};

use crate::ip::IpPacketRef;

use super::TcpPacket;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[repr(u8)]
pub enum TcpState {
    #[default]
    Closed = 0,
    Listen = 1,
    SynSent = 2,
    SynRcvd = 3,
    Established = 4,
    FinWait1 = 5,
    FinWait2 = 6,
    Closing = 7,
    TimeWait = 8,
    CloseWait = 9,
    LastAck = 10,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct TcpSegment {
    pub header: TcpPacket,
    pub seq_no: u32,
    pub len: u32,
}

#[derive(Debug)]
#[non_exhaustive]
pub(super) enum TcpEvent {
    SysListen(),
    SysOpen(SocketAddr),
    SysClose(),
    SysSend(),
    SysRecv(),

    Syn((IpAddr, IpAddr, TcpPacket)),
    Ack((IpAddr, IpAddr, TcpPacket)),
    Fin((IpAddr, IpAddr, TcpPacket)),
    Data((IpAddr, IpAddr, TcpPacket)),
    Perm((IpAddr, IpAddr, TcpPacket)),

    Timeout(),
}

pub enum TcpSyscall {
    Listen(),
    Open(SocketAddr),
    Close(),
    Send,
    Recv,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) enum TcpPacketId {
    Syn,
    Ack,
    Fin,
}
