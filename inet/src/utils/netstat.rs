use std::{io::Result, net::SocketAddr};

use crate::{
    socket::{SocketDomain, SocketType},
    IOContext,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Netstat {
    pub active_connections: Vec<NetstatConnection>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetstatConnection {
    pub proto: NetstatConnectionProto,
    pub recv_q: usize,
    pub send_q: usize,
    pub local_addr: SocketAddr,
    pub foreign_addr: SocketAddr,
    pub state: Option<String>,
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
        use crate::socket::{SocketDomain::*, SocketType::*};
        match (domain, typ) {
            (AF_INET, SOCK_DGRAM) => Self::Udp4,
            (AF_INET6, SOCK_DGRAM) => Self::Udp6,
            (AF_INET, SOCK_STREAM) => Self::Tcp4,
            (AF_INET6, SOCK_STREAM) => Self::Tcp6,
            _ => unreachable!(),
        }
    }
}

pub fn netstat() -> Result<Netstat> {
    IOContext::failable_api(|ctx| Ok(ctx.netstat()))
}

impl IOContext {
    pub fn netstat(&mut self) -> Netstat {
        let mut active_connections = Vec::new();
        for (fd, socket) in self.sockets.iter() {
            use crate::socket::{SocketDomain::*, SocketType::*};

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
                    let Some(mng) = self.tcp.streams.get(fd) else { continue };
                    active_connections.push(NetstatConnection {
                        proto,
                        recv_q: socket.recv_q,
                        send_q: socket.send_q,
                        local_addr: socket.addr,
                        foreign_addr: socket.peer,
                        state: Some(format!("{:?}", mng.state)),
                    })
                }
                _ => unreachable!(),
            }
        }

        Netstat { active_connections }
    }
}
