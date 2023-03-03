use std::{io, net::SocketAddr};

use crate::{
    bsd::{SocketDomain, SocketType},
    tcp::TcpState,
    IOContext,
};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Netstat {
    pub active_connections: Vec<NetstatConnection>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NetstatConnection {
    pub proto: NetstatConnectionProto,
    pub recv_q: usize,
    pub send_q: usize,
    pub local_addr: SocketAddr,
    pub foreign_addr: SocketAddr,
    pub state: Option<TcpState>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NetstatConnectionProto {
    Tcp4,
    Tcp6,
    Udp4,
    Udp6,
}

impl NetstatConnectionProto {
    fn new(domain: SocketDomain, typ: SocketType) -> Self {
        use crate::bsd::{SocketDomain::*, SocketType::*};
        match (domain, typ) {
            (AF_INET, SOCK_DGRAM) => Self::Udp4,
            (AF_INET6, SOCK_DGRAM) => Self::Udp6,
            (AF_INET, SOCK_STREAM) => Self::Tcp4,
            (AF_INET6, SOCK_STREAM) => Self::Tcp6,
            _ => unreachable!(),
        }
    }
}

pub fn netstat() -> io::Result<Netstat> {
    IOContext::try_with_current(|ctx| {
        let mut active_connections = Vec::new();
        for (fd, socket) in &ctx.sockets {
            use crate::bsd::{SocketDomain::*, SocketType::*};

            let proto = NetstatConnectionProto::new(socket.domain, socket.typ);
            match (socket.domain, socket.typ) {
                (AF_INET, SOCK_DGRAM) | (AF_INET6, SOCK_DGRAM) => {
                    active_connections.push(NetstatConnection {
                        proto,
                        recv_q: socket.recv_q,
                        send_q: socket.send_q,
                        local_addr: socket.addr,
                        foreign_addr: socket.peer,
                        state: None,
                    })
                }
                (AF_INET, SOCK_STREAM) | (AF_INET6, SOCK_STREAM) => {
                    let Some(mng) = ctx.tcp_manager.get(fd) else { continue };
                    active_connections.push(NetstatConnection {
                        proto,
                        recv_q: socket.recv_q,
                        send_q: socket.send_q,
                        local_addr: socket.addr,
                        foreign_addr: socket.peer,
                        state: Some(mng.state),
                    })
                }
                _ => unreachable!(),
            }
        }

        Netstat { active_connections }
    })
    .ok_or(io::Error::new(io::ErrorKind::Other, "Missing IO plugin"))
}
