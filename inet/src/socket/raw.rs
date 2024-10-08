use std::{
    collections::hash_map::Entry,
    io::{Error, ErrorKind, Result},
    net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6},
};

use types::ip::IpPacket;
use tokio::sync::mpsc::{self, Receiver, Sender};

use crate::IOContext;

use super::{Fd, SocketDomain};

/// A specialiced socket for capturing custom IP datagrams.
pub struct RawIpSocket {
    fd: Fd,
    rx: Receiver<IpPacket>,
    tx: Sender<IpPacket>,
}

impl RawIpSocket {
    /// Creates a new receiver on the AF_INET domain.
    pub fn new_v4() -> Result<RawIpSocket> {
        IOContext::failable_api(|ctx| ctx.create_raw_ip_socket(SocketDomain::AF_INET))
    }

    /// Creates a new receiver on the AF_INET6 domain.
    pub fn new_v6() -> Result<RawIpSocket> {
        IOContext::failable_api(|ctx| ctx.create_raw_ip_socket(SocketDomain::AF_INET6))
    }

    /// Binds the socket to capture datagrams with a given proto/next_header.
    pub fn bind_proto(&self, proto: u8) -> Result<()> {
        IOContext::failable_api(|ctx| ctx.proto_bind_raw_ip_socket(self.fd, proto, self.tx.clone()))
    }

    /// Unbinds a socket from capturing packets of a certain TOS.
    pub fn unbind_proto(&self, proto: u8) -> Result<()> {
        IOContext::failable_api(|ctx| ctx.proto_unbind_raw_ip_socket(self.fd, proto))
    }

    /// Receives datagrams, if there are any (blockingly).
    pub async fn recv(&mut self) -> Result<IpPacket> {
        self.rx
            .recv()
            .await
            .ok_or(Error::new(ErrorKind::BrokenPipe, "listener closed"))
    }

    /// Non-blockingly receives datagrams, or WouldBlock
    /// if non are present.
    pub fn try_recv(&mut self) -> Result<IpPacket> {
        self.rx
            .try_recv()
            .map_err(|_| Error::new(ErrorKind::WouldBlock, "would block"))
    }

    /// Sends datatgrams using this socket as a sender.
    pub fn try_send(&self, pkt: IpPacket) -> Result<()> {
        IOContext::failable_api(|ctx: &mut IOContext| ctx.raw_socket_send_ip_packet(self.fd, pkt))
    }
}

impl Drop for RawIpSocket {
    fn drop(&mut self) {
        IOContext::try_with_current(|ctx| ctx.drop_raw_ip_socket(self.fd));
    }
}

impl IOContext {
    fn create_raw_ip_socket(&mut self, domain: SocketDomain) -> Result<RawIpSocket> {
        let fd = self.create_socket(domain, super::SocketType::SOCK_RAW, 0)?;

        let saddr = if domain == SocketDomain::AF_INET {
            SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0).into()
        } else {
            SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0).into()
        };

        if let Err(e) = self.bind_socket(fd, saddr) {
            self.close_socket(fd)?;
            return Err(e);
        }

        let (tx, rx) = mpsc::channel(32);
        Ok(RawIpSocket { fd, rx, tx })
    }

    fn proto_bind_raw_ip_socket(&mut self, fd: Fd, proto: u8, tx: Sender<IpPacket>) -> Result<()> {
        let Some(socket) = self.sockets.get(&fd) else {
            return Err(Error::new(ErrorKind::InvalidInput, "no socket under fd"));
        };

        let domain = socket.domain;
        let entry = self.sockets.handlers.entry((proto, domain));
        match entry {
            Entry::Occupied(_) => Err(Error::new(
                ErrorKind::AlreadyExists,
                "filter allready occupied",
            )),
            Entry::Vacant(entry) => {
                entry.insert((fd, tx));
                Ok(())
            }
        }
    }

    fn proto_unbind_raw_ip_socket(&mut self, fd: Fd, proto: u8) -> Result<()> {
        let Some(socket) = self.sockets.get(&fd) else {
            return Err(Error::new(ErrorKind::InvalidInput, "no socket under fd"));
        };

        let domain = socket.domain;
        let removed = self.sockets.handlers.remove(&(proto, domain));
        if removed.is_none() {
            Err(Error::new(ErrorKind::NotFound, "binding does not exist"))
        } else {
            Ok(())
        }
    }

    fn raw_socket_send_ip_packet(&mut self, fd: Fd, pkt: IpPacket) -> Result<()> {
        let Some(socket) = self.sockets.get(&fd) else {
            return Err(Error::new(ErrorKind::InvalidInput, "no socket under fd"));
        };

        self.send_ip_packet(socket.interface.clone(), pkt, true)
    }

    fn drop_raw_ip_socket(&mut self, fd: Fd) {
        self.sockets.handlers.retain(|_, h| h.0 != fd);
        let _ = self.close_socket(fd);
    }
}
