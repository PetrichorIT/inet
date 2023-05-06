use std::{
    io::Error,
    net::{IpAddr, SocketAddr},
};

use inet_types::ip::IpPacketRef;

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

#[derive(Debug)]
#[non_exhaustive]
pub(super) enum TcpEvent {
    SysListen(),
    SysOpen(SocketAddr),
    SysClose(),
    SysSend(),
    SysRecv(),

    Rst((IpAddr, IpAddr, TcpPacket)),
    Syn((IpAddr, IpAddr, TcpPacket)),
    Ack((IpAddr, IpAddr, TcpPacket)),
    Fin((IpAddr, IpAddr, TcpPacket)),
    Data((IpAddr, IpAddr, TcpPacket)),
    Perm((IpAddr, IpAddr, TcpPacket)),

    DestinationUnreachable(Error),
    Timeout(),
}

pub enum TcpSyscall {
    Listen(),
    Open(SocketAddr),
    DestinationUnreachable(Error),
    Close(),
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) enum TcpPacketId {
    Syn,
    Ack,
    Fin,
}
