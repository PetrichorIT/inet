use std::{io::Result, net::SocketAddr};

use crate::{
    socket::{SocketDomain, SocketType},
    IOContext,
};

/// A mapping of all currently active sockets.
///
/// This is the return value of a call to `netstat`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Netstat {
    /// A collection of active sockets.
    pub active_connections: Vec<NetstatConnection>,
}

/// An active socket, within the context of one node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetstatConnection {
    /// The protocol type of the described socket.
    pub proto: NetstatConnectionProto,
    /// The number of bytes that were received on the described socket.
    pub recv_q: usize,
    /// The number of bytes that were send on the described socket.
    pub send_q: usize,
    /// The local adddress of the described socket.
    pub local_addr: SocketAddr,
    /// The foreign address of the described socket, if there is any.
    pub foreign_addr: SocketAddr,
    /// The current state of the socket.
    pub state: Option<String>,
}

/// The protocol type of any socket connection.
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

/// Maps out all active connections on a node.
///
/// This function returns maps out all active connections managed by
/// `inet` on the current node. Note that as of now, only TCP and UDP
/// sockets are recognized.
///
/// # Errors
///
/// This function may fail, if called from outside of a node context.
pub fn netstat() -> Result<Netstat> {
    IOContext::failable_api(|ctx| Ok(ctx.netstat()))
}

impl IOContext {
    pub(crate) fn netstat(&mut self) -> Netstat {
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
