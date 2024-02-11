//! Networking sockets - endpoint for communication.

use fxhash::{FxBuildHasher, FxHashMap};
use inet_types::ip::IpPacket;
use tokio::sync::mpsc::Sender;

use crate::interface::{IfId, InterfaceAddr};

use super::{
    interface::{InterfaceName, InterfaceStatus},
    IOContext,
};
use std::{
    fmt::Display,
    io::{Error, ErrorKind, Result},
};
use std::{
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    ops::{Deref, DerefMut},
};

mod api;
pub use self::api::*;

mod types;
pub use self::types::*;

mod fd;
pub use self::fd::*;

mod raw;
pub use self::raw::*;

#[derive(Debug)]
pub(super) struct Sockets {
    sockets: FxHashMap<Fd, Socket>,
    pub(super) handlers: FxHashMap<(u8, SocketDomain), (Fd, Sender<IpPacket>)>,
}

impl Sockets {
    pub(super) fn new() -> Sockets {
        Sockets {
            sockets: FxHashMap::with_hasher(FxBuildHasher::default()),
            handlers: FxHashMap::with_hasher(FxBuildHasher::default()),
        }
    }
}

impl Deref for Sockets {
    type Target = FxHashMap<Fd, Socket>;
    fn deref(&self) -> &Self::Target {
        &self.sockets
    }
}

impl DerefMut for Sockets {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.sockets
    }
}

#[doc(hidden)]
/// A communications socket.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Socket {
    /// The local (unique) address of the socket.
    pub addr: SocketAddr,
    /// The address of the peer, if can be determined.
    pub peer: SocketAddr,

    /// The domain the socket operates in.
    pub domain: SocketDomain,
    /// The service type provided by the socket.
    pub typ: SocketType,
    /// An indicator which protocol is used, if domain/typ was
    /// not conclusive.
    pub protocol: i32,
    /// The filedescriptor of the socket
    pub fd: Fd,

    /// The binding of the socket
    pub interface: SocketIfaceBinding,
    /// The ttl of IP like packets
    pub ttl: u8,

    /// The total number of bytes received by this socket.
    pub recv_q: usize,
    /// The total number of bytes sent by this socket.
    pub send_q: usize,
}

/// The kind of binding that connects a socket to the NIC.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SocketIfaceBinding {
    /// A socket bound to a specific address of an interface.
    Bound(IfId),
    /// A socket bound to a zero address able to interact with all interfaces.
    Any(Vec<IfId>),
    /// A socket not yet bound
    NotBound,
}

impl SocketIfaceBinding {
    pub fn unwrap_ifid(&self) -> IfId {
        match self {
            Self::Any(ifids) => ifids[0],
            Self::Bound(ifid) => *ifid,
            _ => panic!("unwrap failed"),
        }
    }

    pub fn contains(&self, ifid: &IfId) -> bool {
        match self {
            Self::Any(ifids) => ifids.contains(ifid),
            Self::Bound(sifid) => sifid == ifid,
            _ => false,
        }
    }
}

impl Display for SocketIfaceBinding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotBound => write!(f, "0"),
            Self::Bound(ifid) => write!(f, "{}", ifid),
            Self::Any(_) => write!(f, "IFADDRANY"),
        }
    }
}

impl IOContext {
    const POSIX_ALLOWED_COMBI: [(SocketDomain, SocketType); 8] = [
        (SocketDomain::AF_INET, SocketType::SOCK_DGRAM),
        (SocketDomain::AF_INET6, SocketType::SOCK_DGRAM),
        (SocketDomain::AF_INET, SocketType::SOCK_STREAM),
        (SocketDomain::AF_INET6, SocketType::SOCK_STREAM),
        (SocketDomain::AF_INET, SocketType::SOCK_RAW),
        (SocketDomain::AF_INET6, SocketType::SOCK_RAW),
        (SocketDomain::AF_UNIX, SocketType::SOCK_DGRAM),
        (SocketDomain::AF_UNIX, SocketType::SOCK_STREAM),
    ];

    pub(super) fn fd_generate(&mut self) -> Fd {
        loop {
            self.fd = self.fd.wrapping_add(1);
            if self.sockets.get(&self.fd).is_some() {
                continue;
            }
            return self.fd;
        }
    }

    pub(super) fn create_socket(
        &mut self,
        domain: SocketDomain,
        typ: SocketType,
        protocol: i32,
    ) -> Result<Fd> {
        if !Self::POSIX_ALLOWED_COMBI.contains(&(domain, typ)) {
            return Err(Error::new(
                ErrorKind::Unsupported,
                "socket type is not supported in this domain",
            ));
        }

        let fd = self.fd_generate();
        let socket = Socket {
            addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)),
            peer: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)),

            domain,
            typ,
            protocol,
            fd,
            interface: SocketIfaceBinding::NotBound,
            ttl: 128,

            recv_q: 0,
            send_q: 0,
        };
        tracing::trace!("creating '0x{:x} {:?}/{:?}/{}", fd, domain, typ, protocol);
        self.sockets.insert(fd, socket);
        Ok(fd)
    }

    pub(super) fn dup_socket(&mut self, fd: Fd) -> Result<Fd> {
        let Some(socket) = self.sockets.get(&fd) else {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "invalid fd - socket dropped",
            ));
        };

        let mut new = socket.clone();
        let new_fd = self.fd_generate();
        new.fd = new_fd;
        tracing::trace!(
            "created '0x{:x} {:?}/{:?}/{} from '0x{:x}",
            new_fd,
            new.domain,
            new.typ,
            new.protocol,
            fd
        );

        self.sockets.insert(new_fd, new);

        Ok(new_fd)
    }

    pub(super) fn close_socket(&mut self, fd: Fd) -> Result<()> {
        tracing::trace!("closing '0x{:x}", fd);
        let socket = self.sockets.remove(&fd);
        if socket.is_some() {
            Ok(())
        } else {
            Err(Error::new(ErrorKind::InvalidInput, "invalid fd"))
        }
    }

    pub(super) fn bind_socket(&mut self, fd: Fd, addr: SocketAddr) -> Result<SocketAddr> {
        let unspecified = match addr {
            SocketAddr::V4(v4) => v4.ip().is_unspecified(),
            SocketAddr::V6(v6) => v6.ip().is_unspecified(),
        };

        if unspecified {
            self.bind_socket_unspecified(fd, addr)
        } else {
            self.bind_socket_specified(fd, addr)
        }
    }

    fn bind_socket_unspecified(&mut self, fd: Fd, addr: SocketAddr) -> Result<SocketAddr> {
        let mut interfaces = self
            .ifaces
            .iter()
            .map(|(ifid, i)| (ifid, i, i.prio))
            .collect::<Vec<_>>();

        interfaces.sort_by(|(_, _, l), (_, _, r)| l.cmp(r));

        let mut valid_ifaces = Vec::new();
        for (ifid, interface, _) in interfaces {
            if interface.status == InterfaceStatus::Inactive {
                continue;
            }

            if !interface.flags.up {
                continue;
            }

            if addr.is_ipv4() {
                // 0.0.0.0 binding
                let v4capable = interface
                    .addrs
                    .iter()
                    .any(|addr| matches!(addr, InterfaceAddr::Inet { .. }));
                if v4capable {
                    valid_ifaces.push(*ifid);
                }
            } else {
                let ipcapable = interface.addrs.iter().any(|addr| {
                    matches!(
                        addr,
                        InterfaceAddr::Inet { .. } | InterfaceAddr::Inet6 { .. }
                    )
                });

                if ipcapable {
                    valid_ifaces.push(*ifid);
                }
            }
        }

        if valid_ifaces.is_empty() {
            Err(Error::new(
                ErrorKind::AddrNotAvailable,
                "Address not available",
            ))
        } else {
            let mut port = addr.port();
            if port == 0 {
                port = self.port;
                while self.sockets.iter().any(|(_, s)| s.addr.port() == port) {
                    port = port.wrapping_add(1);
                }
                self.port = port.wrapping_add(1);
            } else {
                if self
                    .sockets
                    .iter()
                    .any(|socket| socket.1.addr.port() == port)
                {
                    return Err(Error::new(ErrorKind::AddrInUse, "Port allready in use"));
                }
            }

            let socket = self.sockets.get_mut(&fd).expect("invalid socket fd");
            socket.addr = SocketAddr::new(addr.ip(), port);
            socket.interface = SocketIfaceBinding::Any(valid_ifaces);

            tracing::trace!(
                "binding '0x{:x} to {} at {} (zero-bind)",
                fd,
                socket.addr,
                socket.interface
            );

            Ok(socket.addr)
        }
    }

    fn bind_socket_specified(&mut self, fd: Fd, addr: SocketAddr) -> Result<SocketAddr> {
        if self.sockets.values().any(|socket| socket.addr == addr) {
            return Err(Error::new(ErrorKind::AddrInUse, "Address allready in use"));
        }
        // Find right interface
        for (ifid, interface) in self.ifaces.iter() {
            if let Some(_) = interface
                .addrs
                .iter()
                .find(|iaddr| iaddr.matches_subnet(addr.ip()))
            {
                // Found the right interface
                if interface.status == InterfaceStatus::Inactive {
                    return Err(Error::new(ErrorKind::NotFound, "Interface inactive"));
                }

                if !interface.flags.up {
                    return Err(Error::new(ErrorKind::NotFound, "Interface down"));
                }

                let next = addr.ip();
                let mut port = addr.port();
                if port == 0 {
                    // Unspecified port
                    let mut naddr = SocketAddr::new(next, port);
                    loop {
                        naddr.set_port(self.port);
                        self.port += 1;

                        if !self.sockets.values().any(|socket| socket.addr == naddr) {
                            break;
                        }
                    }

                    port = naddr.port();
                } else {
                    // Check direct port
                    let naddr = SocketAddr::new(next, port);
                    if self.sockets.values().any(|socket| socket.addr == naddr) {
                        // E_INUSE
                        continue;
                    }
                }

                // Successful bind
                let socket = self.sockets.get_mut(&fd).expect("Invalid socket FD");
                socket.addr = SocketAddr::new(next, port);
                socket.interface = SocketIfaceBinding::Bound(*ifid);

                tracing::trace!(
                    "binding '0x{:x} to {} at {} (directed-bind)",
                    fd,
                    socket.addr,
                    interface.name
                );

                return Ok(socket.addr);
            }
        }

        Err(Error::new(
            ErrorKind::AddrNotAvailable,
            "Address not available",
        ))
    }

    pub(super) fn bind_peer(&mut self, fd: Fd, peer: SocketAddr) -> Result<()> {
        let Some(socket) = self.sockets.get_mut(&fd) else {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "invalid fd - socket dropped",
            ));
        };
        socket.peer = peer;
        Ok(())
    }

    pub(super) fn get_socket_addr(&self, fd: Fd) -> Result<SocketAddr> {
        let Some(socket) = self.sockets.get(&fd) else {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "invalid fd - socket dropped",
            ));
        };
        Ok(socket.addr)
    }

    pub(super) fn get_socket_peer(&self, fd: Fd) -> Result<SocketAddr> {
        let Some(socket) = self.sockets.get(&fd) else {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "invalid fd - socket dropped",
            ));
        };
        if socket.peer.ip().is_unspecified() {
            Err(Error::new(ErrorKind::Other, "invalid peer addr - no peer"))
        } else {
            Ok(socket.peer)
        }
    }

    pub(super) fn socket_link_update(&mut self, fd: Fd, _ifid: IfId) {
        use SocketDomain::*;
        use SocketType::*;

        let Some(socket) = self.sockets.get(&fd) else {
            return;
        };

        match (socket.domain, socket.typ) {
            (AF_INET, SOCK_DGRAM) | (AF_INET6, SOCK_DGRAM) => {
                let Some(udp) = self.udp.binds.get_mut(&fd) else {
                    return;
                };

                if let Some(interest) = &udp.interest {
                    if interest.is_writable() {
                        let interest = udp.interest.take().unwrap();
                        interest.wake()
                    }
                }
            }
            (AF_INET, SOCK_STREAM) | (AF_INET6, SOCK_STREAM) => {
                self.tcp_socket_link_update(fd);
            }
            _ => {}
        }
    }

    pub(super) fn socket_device(&mut self, fd: Fd) -> Result<Option<InterfaceName>> {
        let Some(socket) = self.sockets.get(&fd) else {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "invalid fd - socket dropped",
            ));
        };

        match &socket.interface {
            SocketIfaceBinding::NotBound => Ok(None),
            SocketIfaceBinding::Bound(ifid) => {
                let Some(interface) = self.ifaces.get(&ifid) else {
                    return Err(Error::new(ErrorKind::Other, "interface down"));
                };

                Ok(Some(interface.name.clone()))
            }
            SocketIfaceBinding::Any(ifids) => {
                // SAFTEY: list is never empty
                let ifid = ifids[0];
                let Some(interface) = self.ifaces.get(&ifid) else {
                    return Err(Error::new(ErrorKind::Other, "interface down"));
                };

                Ok(Some(interface.name.clone()))
            }
        }
    }
}
