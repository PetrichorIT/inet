//! Networking sockets - endpoint for communication.

use fxhash::{FxBuildHasher, FxHashMap};
use tokio::sync::mpsc::Sender;
use types::ip::IpPacket;

use crate::interface::IfId;

use super::{IOContext, interface::InterfaceName};
use std::{
    cell::Cell,
    fmt::Display,
    io::{Error, ErrorKind, Result},
};
use std::{
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    ops::{Deref, DerefMut},
};

mod api;
pub use self::api::*;

mod util;
pub use self::util::*;

mod fd;
pub use self::fd::*;

mod raw;
pub use self::raw::*;

use SocketDomain::*;
use SocketType::*;

#[derive(Debug)]
pub(super) struct Sockets {
    pub next_fd: Fd,
    pub next_port: Cell<u16>,
    pub sockets: FxHashMap<Fd, Socket>,
    pub handlers: FxHashMap<(u8, SocketDomain), SocketHandler>,
}

pub type SocketHandler = (Fd, Sender<(IfId, IpPacket)>);

impl Sockets {
    pub(super) fn new() -> Sockets {
        Sockets {
            next_fd: 100,
            next_port: Cell::new(1024),
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
            self.sockets.next_fd = self.sockets.next_fd.wrapping_add(1);
            if self.sockets.get(&self.sockets.next_fd).is_some() {
                continue;
            }
            return self.sockets.next_fd;
        }
    }

    pub(super) fn socket(
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

    pub(super) fn socket_duplicate(&mut self, fd: Fd) -> Result<Fd> {
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

    pub(super) fn socket_close(&mut self, fd: Fd) -> Result<()> {
        tracing::trace!("closing '0x{:x}", fd);
        if self.sockets.remove(&fd).is_some() {
            Ok(())
        } else {
            Err(Error::new(ErrorKind::InvalidInput, "invalid fd"))
        }
    }

    pub(super) fn socket_bind(&mut self, fd: Fd, addr: SocketAddr) -> Result<SocketAddr> {
        let unspecified = match addr {
            SocketAddr::V4(v4) => v4.ip().is_unspecified(),
            SocketAddr::V6(v6) => v6.ip().is_unspecified(),
        };

        if unspecified {
            self.socket_bind_unspecified(fd, addr)
        } else {
            self.socket_bind_specified(fd, addr)
        }
    }

    fn socket_bind_unspecified(&mut self, fd: Fd, addr: SocketAddr) -> Result<SocketAddr> {
        let Some(socket) = self.sockets.get(&fd) else {
            return Err(Error::new(ErrorKind::InvalidInput, "invalid fd"));
        };

        let mut available_ifaces = self.ifaces.iter().collect::<Vec<_>>();
        available_ifaces.sort_by_key(|(_, iface)| iface.state.prio);

        let valid_ifaces = available_ifaces
            .iter()
            .filter_map(|(ifid, iface)| {
                let ifid = **ifid;
                if !iface.flags.up {
                    return None;
                }

                if addr.is_ipv4() {
                    iface.bindings.has_v4_capability().then_some(ifid)
                } else {
                    ((iface.bindings.has_v4_capability() || iface.bindings.has_v6_capability())
                        && iface.flags.v6)
                        .then_some(ifid)
                }
            })
            .collect::<Vec<_>>();

        if valid_ifaces.is_empty() {
            return Err(Error::new(
                ErrorKind::AddrNotAvailable,
                "address not available",
            ));
        }

        let mut port = addr.port();
        if port == 0 {
            port = self.sockets.next_port.get();
            while self
                .sockets
                .values()
                .any(|other| other.addr.port() == port && other.typ == socket.typ)
            {
                port = port.wrapping_add(1);
            }
            self.sockets.next_port.set(port.wrapping_add(1));
        } else if self
            .sockets
            .values()
            .any(|other| other.addr.port() == port && other.typ == socket.typ)
        {
            return Err(Error::new(ErrorKind::AddrInUse, "port already in use"));
        }

        let socket = self.sockets.get_mut(&fd).expect("unreachable");
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

    fn socket_bind_specified(&mut self, fd: Fd, addr: SocketAddr) -> Result<SocketAddr> {
        let Some(socket) = self.sockets.get(&fd) else {
            return Err(Error::new(ErrorKind::InvalidInput, "invalid fd"));
        };

        if self
            .sockets
            .values()
            .any(|other| other.addr == addr && other.typ == socket.typ)
        {
            return Err(Error::new(ErrorKind::AddrInUse, "address already in use"));
        }

        // Find right interface
        for (ifid, interface) in self
            .ifaces
            .iter()
            .filter(|(_, iface)| iface.bindings.matches(addr.ip()))
        {
            if !interface.flags.up {
                continue;
            }

            let next = addr.ip();
            let mut port = addr.port();
            if port == 0 {
                // Unspecified port
                let mut naddr = SocketAddr::new(next, port);
                loop {
                    let port = self.sockets.next_port.get();
                    naddr.set_port(port);
                    self.sockets.next_port.set(port + 1);

                    if !self
                        .sockets
                        .values()
                        .any(|other| other.addr == naddr && other.typ == socket.typ)
                    {
                        break;
                    }
                }

                port = naddr.port();
            } else {
                // Check direct port
                let naddr = SocketAddr::new(next, port);
                if self
                    .sockets
                    .values()
                    .any(|other| other.addr == naddr && other.typ == socket.typ)
                {
                    // E_INUSE
                    continue;
                }
            }

            // Successful bind
            let socket = self.sockets.get_mut(&fd).expect("unreachable");
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

        Err(Error::new(
            ErrorKind::AddrNotAvailable,
            "Address not available",
        ))
    }

    pub(super) fn socket_set_peer(&mut self, fd: Fd, peer: SocketAddr) -> Result<()> {
        let Some(socket) = self.sockets.get_mut(&fd) else {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "invalid fd - socket dropped",
            ));
        };

        if socket.addr.is_ipv4() != peer.is_ipv4() {
            return Err(Error::new(
                ErrorKind::AddrNotAvailable,
                "address not available - ip version missmatch",
            ));
        }

        socket.peer = peer;
        Ok(())
    }

    pub(super) fn socket_get_addr(&self, fd: Fd) -> Result<SocketAddr> {
        let Some(socket) = self.sockets.get(&fd) else {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "invalid fd - socket dropped",
            ));
        };
        Ok(socket.addr)
    }

    pub(super) fn socket_get_peer(&self, fd: Fd) -> Result<SocketAddr> {
        let Some(socket) = self.sockets.get(&fd) else {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "invalid fd - socket dropped",
            ));
        };
        if socket.peer.ip().is_unspecified() {
            Err(Error::new(
                ErrorKind::NotConnected,
                "invalid peer addr - no peer",
            ))
        } else {
            Ok(socket.peer)
        }
    }

    pub(super) fn socket_link_update(&mut self, fd: Fd, _ifid: IfId) {
        let Some(socket) = self.sockets.get(&fd) else {
            return;
        };

        match (socket.domain, socket.typ) {
            (AF_INET, SOCK_DGRAM) | (AF_INET6, SOCK_DGRAM) => {
                let Some(udp) = self.udp.binds.get_mut(&fd) else {
                    return;
                };

                udp.on_write_ready();
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
                let Some(interface) = self.ifaces.get(ifid) else {
                    return Err(Error::other("interface down"));
                };

                Ok(Some(interface.name.clone()))
            }
            SocketIfaceBinding::Any(ifids) => {
                // SAFTEY: list is never empty
                let ifid = ifids[0];
                let Some(interface) = self.ifaces.get(&ifid) else {
                    return Err(Error::other("interface down"));
                };

                Ok(Some(interface.name.clone()))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::interface::{InterfaceDef, NetworkDevice};
    use des::prelude::ModuleId;
    use std::net::Ipv6Addr;

    #[test]
    fn create_supported() {
        let mut ctx = IOContext::new(ModuleId::NULL);
        for (domain, typ) in IOContext::POSIX_ALLOWED_COMBI {
            let sock = ctx.socket(domain, typ, 0);
            assert!(sock.is_ok());
        }
    }

    #[test]
    fn create_not_supported() {
        let mut ctx = IOContext::new(ModuleId::NULL);
        assert_eq!(
            ctx.socket(AF_UNIX, SOCK_RDM, 0)
                .expect_err("must fail")
                .kind(),
            ErrorKind::Unsupported
        );
    }

    #[test]
    fn duplicate() -> Result<()> {
        let mut ctx = IOContext::new(ModuleId::NULL);
        let fd = ctx.socket(AF_INET, SOCK_DGRAM, 0)?;
        let dup = ctx.socket_duplicate(fd)?;

        assert_ne!(fd, dup);
        let mut sock = ctx.sockets.get(&fd).unwrap().clone();
        let mut dup_sock = ctx.sockets.get(&dup).unwrap().clone();
        sock.fd = 0;
        dup_sock.fd = 0;

        assert_eq!(sock, dup_sock);

        Ok(())
    }

    #[test]
    fn duplicate_socket_does_not_exist() -> Result<()> {
        let mut ctx = IOContext::new(ModuleId::NULL);
        let fd = ctx.socket(AF_INET, SOCK_DGRAM, 0)?;
        let dup = ctx.socket_duplicate(fd + 1);
        assert_eq!(dup.unwrap_err().kind(), ErrorKind::InvalidInput);

        Ok(())
    }

    #[test]
    fn close() -> Result<()> {
        let mut ctx = IOContext::new(ModuleId::NULL);
        let fd = ctx.socket(AF_INET, SOCK_DGRAM, 0)?;
        assert!(ctx.sockets.get(&fd).is_some());
        ctx.socket_close(fd)?;
        assert!(ctx.sockets.get(&fd).is_none());
        Ok(())
    }

    #[test]
    fn close_socket_does_not_exist() -> Result<()> {
        let mut ctx = IOContext::new(ModuleId::NULL);
        let fd = ctx.socket(AF_INET, SOCK_DGRAM, 0)?;
        assert!(ctx.sockets.get(&fd).is_some());
        let error = ctx.socket_close(fd + 1).expect_err("must be an error");
        assert_eq!(error.kind(), ErrorKind::InvalidInput);
        assert!(ctx.sockets.get(&fd).is_some());
        Ok(())
    }

    impl IOContext {
        fn mock_add_interface(&mut self, iface: InterfaceDef) -> Result<()> {
            self.ifaces.insert(iface.name.id(), iface.into_legacy());
            Ok(())
        }
    }

    #[test]
    fn bind_specified() -> Result<()> {
        let mut ctx = IOContext::new(ModuleId::NULL);
        ctx.mock_add_interface(
            InterfaceDef::new("en0", NetworkDevice::loopback())
                .ip(Ipv4Addr::new(192, 168, 2, 101).into()),
        )?;
        ctx.mock_add_interface(
            InterfaceDef::new("en1", NetworkDevice::loopback())
                .ip(Ipv4Addr::new(10, 100, 28, 101).into()),
        )?;

        // port0 bind
        let fd = ctx.socket(AF_INET, SOCK_DGRAM, 0)?;
        let addr = SocketAddr::new(Ipv4Addr::new(192, 168, 2, 101).into(), 0);
        ctx.socket_bind(fd, addr)?;

        let fd = ctx.socket(AF_INET, SOCK_DGRAM, 0)?;
        let addr = SocketAddr::new(Ipv4Addr::new(10, 100, 28, 101).into(), 0);
        ctx.socket_bind(fd, addr)?;

        // portx bind
        let fd = ctx.socket(AF_INET, SOCK_DGRAM, 0)?;
        let addr = SocketAddr::new(Ipv4Addr::new(192, 168, 2, 101).into(), 9314);
        ctx.socket_bind(fd, addr)?;

        let fd = ctx.socket(AF_INET, SOCK_DGRAM, 0)?;
        let addr = SocketAddr::new(Ipv4Addr::new(10, 100, 28, 101).into(), 8351);
        ctx.socket_bind(fd, addr)?;

        Ok(())
    }

    #[test]
    fn bind_specifed_socket_does_not_exist() -> Result<()> {
        let mut ctx = IOContext::new(ModuleId::NULL);
        ctx.mock_add_interface(
            InterfaceDef::new("en0", NetworkDevice::loopback())
                .ip(Ipv4Addr::new(192, 168, 2, 101).into()),
        )?;

        let fd = ctx.socket(AF_INET, SOCK_DGRAM, 0)?;
        let addr = SocketAddr::new(Ipv4Addr::new(192, 168, 2, 101).into(), 2000);
        let error = ctx.socket_bind(fd + 1, addr).expect_err("must be an error");
        assert_eq!(error.kind(), ErrorKind::InvalidInput);

        Ok(())
    }

    #[test]
    fn bind_specifed_address_already_exist() -> Result<()> {
        let mut ctx = IOContext::new(ModuleId::NULL);
        ctx.mock_add_interface(
            InterfaceDef::new("en0", NetworkDevice::loopback())
                .ip(Ipv4Addr::new(192, 168, 2, 101).into()),
        )?;

        let fd = ctx.socket(AF_INET, SOCK_DGRAM, 0)?;
        let addr = SocketAddr::new(Ipv4Addr::new(192, 168, 2, 101).into(), 2000);
        ctx.socket_bind(fd, addr)?;

        let fd = ctx.socket(AF_INET, SOCK_DGRAM, 0)?;
        let error = ctx.socket_bind(fd, addr).expect_err("must fail");
        assert_eq!(error.kind(), ErrorKind::AddrInUse);

        Ok(())
    }

    #[test]
    fn bind_specifed_address_not_available() -> Result<()> {
        let mut ctx = IOContext::new(ModuleId::NULL);
        ctx.mock_add_interface(
            InterfaceDef::new("en0", NetworkDevice::loopback())
                .ip(Ipv4Addr::new(192, 168, 2, 101).into()),
        )?;

        let fd = ctx.socket(AF_INET, SOCK_DGRAM, 0)?;
        let addr = SocketAddr::new(Ipv4Addr::new(10, 1, 1, 2).into(), 2000);
        let error = ctx.socket_bind(fd, addr).expect_err("must be an error");
        assert_eq!(error.kind(), ErrorKind::AddrNotAvailable);

        Ok(())
    }

    #[test]
    fn bind_unspecifed() -> Result<()> {
        let mut ctx = IOContext::new(ModuleId::NULL);
        ctx.mock_add_interface(
            InterfaceDef::new("en0", NetworkDevice::loopback())
                .ip(Ipv4Addr::new(192, 168, 2, 101).into()),
        )?;

        let fd = ctx.socket(AF_INET, SOCK_DGRAM, 0)?;
        let addr = SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 2000);
        ctx.socket_bind(fd, addr)?;

        assert_eq!(
            ctx.sockets.sockets.get(&fd).map(|s| &s.interface),
            Some(&SocketIfaceBinding::Any(vec![
                InterfaceName::new("en0").id()
            ]))
        );

        Ok(())
    }

    #[test]
    fn bind_unspecified_socket_does_not_exist() -> Result<()> {
        let mut ctx = IOContext::new(ModuleId::NULL);
        ctx.mock_add_interface(
            InterfaceDef::new("en0", NetworkDevice::loopback())
                .ip(Ipv4Addr::new(192, 168, 2, 101).into()),
        )?;

        let fd = ctx.socket(AF_INET, SOCK_DGRAM, 0)?;
        let addr = SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 2000);
        let error = ctx.socket_bind(fd + 1, addr).expect_err("must be an error");
        assert_eq!(error.kind(), ErrorKind::InvalidInput);

        Ok(())
    }

    #[test]
    fn bind_unspecified_address_not_available() -> Result<()> {
        let mut ctx = IOContext::new(ModuleId::NULL);
        ctx.mock_add_interface(InterfaceDef::ethv6_autocfg(NetworkDevice::loopback()))?;

        let fd = ctx.socket(AF_INET, SOCK_DGRAM, 0)?;
        let addr = SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 2000);
        let error = ctx.socket_bind(fd, addr).expect_err("must be an error");
        assert_eq!(error.kind(), ErrorKind::AddrNotAvailable);

        Ok(())
    }

    #[test]
    fn bind_unspecified_address_already_in_use() -> Result<()> {
        let mut ctx = IOContext::new(ModuleId::NULL);
        ctx.mock_add_interface(
            InterfaceDef::new("en0", NetworkDevice::loopback())
                .ip(Ipv4Addr::new(192, 168, 2, 101).into()),
        )?;
        let fd = ctx.socket(AF_INET, SOCK_DGRAM, 0)?;
        let addr = SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 2000);
        ctx.socket_bind(fd, addr)?;

        let fd = ctx.socket(AF_INET, SOCK_DGRAM, 0)?;
        let error = ctx.socket_bind(fd, addr).expect_err("must be an error");
        assert_eq!(error.kind(), ErrorKind::AddrInUse);

        Ok(())
    }

    #[test]
    fn bind_different_sockets_bind_to_same_port() -> Result<()> {
        let mut ctx = IOContext::new(ModuleId::NULL);
        ctx.mock_add_interface(
            InterfaceDef::new("en0", NetworkDevice::loopback())
                .ip(Ipv4Addr::new(192, 168, 2, 101).into()),
        )?;

        let addr = SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 2000);

        let fd = ctx.socket(AF_INET, SOCK_STREAM, 0)?;
        let bind1 = ctx.socket_bind(fd, addr)?;

        let fd = ctx.socket(AF_INET, SOCK_DGRAM, 0)?;
        let bind2 = ctx.socket_bind(fd, addr)?;

        assert_eq!(bind1, bind2);

        Ok(())
    }

    #[test]
    fn set_peer() -> Result<()> {
        let mut ctx = IOContext::new(ModuleId::NULL);
        ctx.mock_add_interface(
            InterfaceDef::new("en0", NetworkDevice::loopback())
                .ip(Ipv4Addr::new(192, 168, 2, 101).into()),
        )?;

        let addr = SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 2000);

        let fd = ctx.socket(AF_INET, SOCK_STREAM, 0)?;
        ctx.socket_bind(fd, addr)?;

        let peer = SocketAddr::new(Ipv4Addr::new(10, 1, 1, 10).into(), 9713);
        ctx.socket_set_peer(fd, peer)?;

        assert_eq!(ctx.sockets.sockets.get(&fd).map(|s| s.peer), Some(peer));
        assert_eq!(ctx.socket_get_peer(fd)?, peer);

        Ok(())
    }

    #[test]
    fn set_peer_ip_missmatch() -> Result<()> {
        let mut ctx = IOContext::new(ModuleId::NULL);
        ctx.mock_add_interface(
            InterfaceDef::new("en0", NetworkDevice::loopback())
                .ip(Ipv4Addr::new(192, 168, 2, 101).into()),
        )?;

        let addr = SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 2000);

        let fd = ctx.socket(AF_INET, SOCK_STREAM, 0)?;
        ctx.socket_bind(fd, addr)?;

        let peer = SocketAddr::new(Ipv6Addr::new(0xfe80, 0, 0, 3, 3, 31, 73, 1).into(), 9713);
        let error = ctx.socket_set_peer(fd, peer).expect_err("must be an error");
        assert_eq!(error.kind(), ErrorKind::AddrNotAvailable);

        Ok(())
    }

    #[test]
    fn get_peer_no_peer() -> Result<()> {
        let mut ctx = IOContext::new(ModuleId::NULL);
        ctx.mock_add_interface(
            InterfaceDef::new("en0", NetworkDevice::loopback())
                .ip(Ipv4Addr::new(192, 168, 2, 101).into()),
        )?;

        let addr = SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 2000);

        let fd = ctx.socket(AF_INET, SOCK_STREAM, 0)?;
        ctx.socket_bind(fd, addr)?;

        let error = ctx.socket_get_peer(fd).expect_err("must be an error");
        assert_eq!(error.kind(), ErrorKind::NotConnected);

        Ok(())
    }
}
