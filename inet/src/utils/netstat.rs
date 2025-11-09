use std::{io, net::SocketAddr};

use crate::{
    IOContext, ioctx,
    socket::{SocketDomain, SocketType},
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
    Raw4,
    Raw6,
}

impl NetstatConnectionProto {
    fn new(domain: SocketDomain, typ: SocketType) -> Self {
        use crate::socket::{SocketDomain::*, SocketType::*};
        match (domain, typ) {
            (AF_INET, SOCK_DGRAM) => Self::Udp4,
            (AF_INET6, SOCK_DGRAM) => Self::Udp6,
            (AF_INET, SOCK_STREAM) => Self::Tcp4,
            (AF_INET6, SOCK_STREAM) => Self::Tcp6,
            (AF_INET, SOCK_RAW) => Self::Raw4,
            (AF_INET6, SOCK_RAW) => Self::Raw6,
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
pub fn netstat() -> io::Result<Netstat> {
    ioctx().do_failable(|ctx| Ok(ctx.netstat()))
}

// TODO: netstat does not show listeners apparently

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
                        recv_q: socket.recv_q.get(),
                        send_q: socket.send_q.get(),
                        local_addr: socket.addr,
                        foreign_addr: socket.peer,
                        state: None,
                    });
                }
                (AF_INET, SOCK_STREAM) | (AF_INET6, SOCK_STREAM) => {
                    let Some(mng) = self.tcp.streams.get(fd) else {
                        continue;
                    };
                    active_connections.push(NetstatConnection {
                        proto,
                        recv_q: socket.recv_q.get(),
                        send_q: socket.send_q.get(),
                        local_addr: socket.addr,
                        foreign_addr: socket.peer,
                        state: Some(format!("{:?}", mng.state)),
                    });
                }
                (AF_INET, SOCK_RAW) | (AF_INET6, SOCK_RAW) => {
                    active_connections.push(NetstatConnection {
                        proto,
                        recv_q: socket.recv_q.get(),
                        send_q: socket.send_q.get(),
                        local_addr: socket.addr,
                        foreign_addr: socket.peer,
                        state: None,
                    });
                }
                _ => unreachable!(),
            }
        }

        Netstat { active_connections }
    }
}

#[cfg(test)]
mod tests {
    use des::runtime::RuntimeError;
    use serial_test::serial;

    use crate::{
        UdpSocket,
        tcp::{TcpListener, TcpStream},
        utils::SimpleSim,
        utils::{NetstatConnection, netstat},
    };

    #[test]
    #[serial]
    fn test_netstat() -> Result<(), RuntimeError> {
        let mut sim = SimpleSim::default();
        sim.node("192.168.2.1", || async move {
            let udp_sock1 = UdpSocket::bind("0.0.0.0:80").await?;
            let udp_sock2 = UdpSocket::bind("0.0.0.0:440").await?;
            udp_sock2.connect("101.1.34.1:9000").await?;

            let tcp_lis = TcpListener::bind("0.0.0.0:40").await?;
            let tcp_str = TcpStream::connect("192.168.2.2:8000").await?;

            let stat = netstat()?;
            assert_eq!(
                stat.active_connections[0],
                NetstatConnection {
                    proto: netstat::NetstatConnectionProto::Tcp4,
                    local_addr: "192.168.2.1:1024".parse().unwrap(),
                    foreign_addr: "192.168.2.2:8000".parse().unwrap(),
                    state: Some("Estab".to_string()),
                    recv_q: 0,
                    send_q: 0,
                }
            );
            assert_eq!(
                stat.active_connections[1],
                NetstatConnection {
                    proto: netstat::NetstatConnectionProto::Udp4,
                    local_addr: "0.0.0.0:80".parse().unwrap(),
                    foreign_addr: "0.0.0.0:0".parse().unwrap(),
                    state: None,
                    recv_q: 0,
                    send_q: 0,
                }
            );
            assert_eq!(
                stat.active_connections[2],
                NetstatConnection {
                    proto: netstat::NetstatConnectionProto::Udp4,
                    local_addr: "0.0.0.0:440".parse().unwrap(),
                    foreign_addr: "101.1.34.1:9000".parse().unwrap(),
                    state: None,
                    recv_q: 0,
                    send_q: 0,
                }
            );

            drop((udp_sock1, udp_sock2, tcp_lis, tcp_str));
            Ok(())
        });

        sim.node("192.168.2.2", || async move {
            let _ = TcpListener::bind("0.0.0.0:8000").await?.accept().await?;
            Ok(())
        });

        sim.run()
    }
}
