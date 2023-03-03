//! BSD sockets.

use super::{
    interface::{InterfaceName, InterfaceStatus},
    IOContext,
};
use std::io::{Error, ErrorKind, Result};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

mod api;
pub use api::*;

mod types;
pub use types::*;

mod fd;
pub use fd::*;

#[doc(hidden)]
/// A communications socket.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Socket {
    pub addr: SocketAddr,
    pub peer: SocketAddr,

    pub domain: SocketDomain,
    pub typ: SocketType,
    pub protocol: i32,
    pub fd: Fd,
    pub interface: u64,

    pub recv_q: usize,
    pub send_q: usize,
}

impl IOContext {
    const POSIX_ALLOWED_COMBI: [(SocketDomain, SocketType); 4] = [
        (SocketDomain::AF_INET, SocketType::SOCK_DGRAM),
        (SocketDomain::AF_INET6, SocketType::SOCK_DGRAM),
        (SocketDomain::AF_INET, SocketType::SOCK_STREAM),
        (SocketDomain::AF_INET6, SocketType::SOCK_STREAM),
    ];

    pub(super) fn bsd_create_socket(
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

        let fd = self.create_fd();
        let socket = Socket {
            addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)),
            peer: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)),

            domain,
            typ,
            protocol,
            fd,
            interface: 0,

            recv_q: 0,
            send_q: 0,
        };
        log::trace!(
            target: "inet/bsd",
            "socket::create '0x{:x} {:?}/{:?}/{}",
            fd,
            domain,
            typ,
            protocol
        );
        self.sockets.insert(fd, socket);
        Ok(fd)
    }

    pub(super) fn bsd_dup_socket(&mut self, fd: Fd) -> Result<Fd> {
        let Some(socket) = self.sockets.get(&fd) else {
            return Err(Error::new(ErrorKind::InvalidInput, "invalid fd - socket dropped"))
        };

        let mut new = socket.clone();
        let new_fd = self.create_fd();
        new.fd = new_fd;
        log::trace!(
            target: "inet/bsd",
            "socket::create '0x{:x} {:?}/{:?}/{} from '0x{:x}",
            new_fd,
            new.domain,
            new.typ,
            new.protocol,
            fd
        );

        self.sockets.insert(new_fd, new);

        Ok(new_fd)
    }

    pub(super) fn bsd_close_socket(&mut self, fd: Fd) -> Result<()> {
        log::trace!( target: "inet/bsd", "socket::close '0x{:x}", fd);
        let socket = self.sockets.remove(&fd);
        if socket.is_some() {
            Ok(())
        } else {
            Err(Error::new(ErrorKind::InvalidInput, "invalid fd"))
        }
    }

    pub(super) fn bsd_bind_socket(&mut self, fd: Fd, addr: SocketAddr) -> Result<SocketAddr> {
        let unspecified = match addr {
            SocketAddr::V4(v4) => v4.ip().is_unspecified(),
            SocketAddr::V6(v6) => v6.ip().is_unspecified(),
        };

        if unspecified {
            self.bsd_bind_socket_unspecified(fd, addr)
        } else {
            self.bsd_bind_socket_specified(fd, addr)
        }
    }

    fn bsd_bind_socket_unspecified(&mut self, fd: Fd, addr: SocketAddr) -> Result<SocketAddr> {
        let socket = self.sockets.get(&fd).expect("Invalid socket FD");
        let domain = socket.domain;

        let mut interfaces = self
            .interfaces
            .iter()
            .map(|(ifid, i)| (ifid, i, i.prio))
            .collect::<Vec<_>>();

        interfaces.sort_by(|(_, _, l), (_, _, r)| l.cmp(r));

        for (ifid, interface, _) in interfaces {
            if interface.status == InterfaceStatus::Inactive {
                continue;
            }

            if !interface.flags.up {
                continue;
            }

            for iaddr in &interface.addrs {
                if !domain.valid_for_interface_addr(iaddr) {
                    continue;
                }
                let Some(next) = iaddr.next_ip() else {
                    continue
                };

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
                socket.interface = *ifid;

                log::trace!(
                    target: "inet/bsd",
                    "socket::bind '0x{:x} to {} at {} (zero-bind)",
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

    fn bsd_bind_socket_specified(&mut self, fd: Fd, addr: SocketAddr) -> Result<SocketAddr> {
        if self.sockets.values().any(|socket| socket.addr == addr) {
            return Err(Error::new(ErrorKind::AddrInUse, "Address allready in use"));
        }
        // Find right interface
        for (ifid, interface) in self.interfaces.iter() {
            if let Some(_iaddr) = interface
                .addrs
                .iter()
                .find(|iaddr| iaddr.matches_ip(addr.ip()))
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
                socket.interface = *ifid;

                log::trace!(
                    target: "inet/bsd",
                    "socket::bind '0x{:x} to {} at {} (directed-bind)",
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

    pub(super) fn bsd_bind_peer(&mut self, fd: Fd, peer: SocketAddr) -> Result<()> {
        let Some(socket) = self.sockets.get_mut(&fd) else {
            return Err(Error::new(ErrorKind::InvalidInput, "invalid fd - socket dropped"))
        };
        socket.peer = peer;
        Ok(())
    }

    pub(super) fn bsd_get_socket_addr(&self, fd: Fd) -> Result<SocketAddr> {
        let Some(socket) = self.sockets.get(&fd) else {
            return Err(Error::new(ErrorKind::InvalidInput, "invalid fd - socket dropped"))
        };
        if socket.addr.ip().is_unspecified() {
            Err(Error::new(
                ErrorKind::Other,
                "invalid local addr - not bound",
            ))
        } else {
            Ok(socket.addr)
        }
    }

    pub(super) fn bsd_get_socket_peer(&self, fd: Fd) -> Result<SocketAddr> {
        let Some(socket) = self.sockets.get(&fd) else {
            return Err(Error::new(ErrorKind::InvalidInput, "invalid fd - socket dropped"))
        };
        if socket.peer.ip().is_unspecified() {
            Err(Error::new(ErrorKind::Other, "invalid peer addr - no peer"))
        } else {
            Ok(socket.peer)
        }
    }

    pub(super) fn bsd_socket_link_update(&mut self, fd: Fd) {
        use SocketDomain::*;
        use SocketType::*;

        let Some(socket) = self.sockets.get(&fd) else {
            return;
        };

        match (socket.domain, socket.typ) {
            (AF_INET, SOCK_DGRAM) | (AF_INET6, SOCK_DGRAM) => {
                let Some(udp) = self.udp_manager.get_mut(&fd) else {
                    return
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

    pub(super) fn bsd_socket_device(&mut self, fd: Fd) -> Result<Option<InterfaceName>> {
        let Some(socket) = self.sockets.get(&fd) else {
            return Err(Error::new(ErrorKind::InvalidInput, "invalid fd - socket dropped"))
        };

        if socket.interface == 0 {
            return Ok(None);
        }

        let Some(interface) = self.interfaces.get(&socket.interface) else {
            return Err(Error::new(ErrorKind::Other, "interface down"))
        };

        Ok(Some(interface.name.clone()))
    }
}
