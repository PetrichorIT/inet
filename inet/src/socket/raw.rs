use std::{
    collections::hash_map::Entry,
    fmt::Debug,
    io::{self, Error, ErrorKind},
};

use tokio::sync::mpsc::{self, Receiver, Sender};
use types::ip::IpPacket;

use crate::{IOContext, IOHandle, interface::IfId};

use super::{Fd, SocketDomain};

/// A specialiced socket for capturing custom IP datagrams.
pub struct RawIpSocket {
    handle: IOHandle,
    fd: Fd,
    rx: Receiver<(IfId, IpPacket)>,
    tx: Sender<(IfId, IpPacket)>,
}

impl RawIpSocket {
    /// Creates a new receiver on the AF_INET domain.
    pub fn new_v4() -> io::Result<RawIpSocket> {
        let handle = IOHandle::current();
        handle.do_failable(|ctx| ctx.create_raw_ip_socket(SocketDomain::AF_INET))
    }

    /// Creates a new receiver on the AF_INET6 domain.
    pub fn new_v6() -> io::Result<RawIpSocket> {
        let handle = IOHandle::current();
        handle.do_failable(|ctx| ctx.create_raw_ip_socket(SocketDomain::AF_INET6))
    }

    /// Binds the socket to capture datagrams with a given proto/next_header.
    pub fn bind_proto(&self, proto: u8) -> io::Result<()> {
        self.handle
            .do_failable(|ctx| ctx.proto_bind_raw_ip_socket(self.fd, proto, self.tx.clone()))
    }

    /// Unbinds a socket from capturing packets of a certain TOS.
    pub fn unbind_proto(&self, proto: u8) -> io::Result<()> {
        self.handle
            .do_failable(|ctx| ctx.proto_unbind_raw_ip_socket(self.fd, proto))
    }

    /// Receives datagrams, if there are any (blockingly).
    pub async fn recv(&mut self) -> io::Result<(IfId, IpPacket)> {
        self.rx
            .recv()
            .await
            .ok_or(Error::new(ErrorKind::BrokenPipe, "listener closed"))
    }

    /// Non-blockingly receives datagrams, or WouldBlock
    /// if non are present.
    pub fn try_recv(&mut self) -> io::Result<(IfId, IpPacket)> {
        self.rx
            .try_recv()
            .map_err(|_| Error::new(ErrorKind::WouldBlock, "would block"))
    }

    /// Sends datatgrams using this socket as a sender.
    pub fn try_send(&self, pkt: IpPacket) -> io::Result<()> {
        self.handle
            .do_failable(|ctx: &mut IOContext| ctx.raw_socket_send_ip_packet(self.fd, pkt))
    }
}

impl Debug for RawIpSocket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RawIpSocket").finish()
    }
}

impl Drop for RawIpSocket {
    fn drop(&mut self) {
        self.handle.try_do_io(|ctx| ctx.drop_raw_ip_socket(self.fd));
    }
}

impl IOContext {
    fn create_raw_ip_socket(&mut self, domain: SocketDomain) -> io::Result<RawIpSocket> {
        let fd = self.socket_create(domain, super::SocketType::SOCK_RAW, 0)?;
        let saddr = domain.addr_unspecified();

        if let Err(e) = self.socket_bind(fd, saddr) {
            self.socket_close(fd)?;
            return Err(e);
        }

        let (tx, rx) = mpsc::channel(32);
        Ok(RawIpSocket {
            fd,
            rx,
            tx,
            handle: self.handle(),
        })
    }

    fn proto_bind_raw_ip_socket(
        &mut self,
        fd: Fd,
        proto: u8,
        tx: Sender<(IfId, IpPacket)>,
    ) -> io::Result<()> {
        let socket = self.sockets.get(fd)?;
        let domain = socket.domain;
        let entry = self.sockets.handlers.entry((proto, domain));
        match entry {
            Entry::Occupied(_) => Err(Error::new(
                ErrorKind::AlreadyExists,
                "filter already occupied",
            )),
            Entry::Vacant(entry) => {
                entry.insert((fd, tx));
                Ok(())
            }
        }
    }

    fn proto_unbind_raw_ip_socket(&mut self, fd: Fd, proto: u8) -> io::Result<()> {
        let socket = self.sockets.get(fd)?;
        let domain = socket.domain;
        let removed = self.sockets.handlers.remove(&(proto, domain));
        if removed.is_none() {
            Err(Error::new(ErrorKind::NotFound, "binding does not exist"))
        } else {
            Ok(())
        }
    }

    fn raw_socket_send_ip_packet(&mut self, fd: Fd, pkt: IpPacket) -> io::Result<()> {
        let socket = self.sockets.get(fd)?;
        match pkt {
            IpPacket::V4(pkt) => self.ipv4_send(socket.interface.into_ifspec(), pkt),
            IpPacket::V6(pkt) => self.ipv6_send(pkt, socket.interface.into_ifspec()),
        }
    }

    fn drop_raw_ip_socket(&mut self, fd: Fd) {
        self.sockets.handlers.retain(|_, h| h.0 != fd);
        let _ = self.socket_close(fd);
    }
}

#[cfg(test)]
mod tests {
    use std::{
        net::{IpAddr, Ipv4Addr, Ipv6Addr},
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };

    use bytes_io::Bytes;
    use des::{
        runtime::{RuntimeError, random},
        time::sleep,
    };
    use serial_test::serial;
    use tokio::spawn;
    use types::ip::{Ipv4Flags, Ipv4Packet, Ipv6Packet};

    use crate::{
        interface::{InterfaceDef, NetworkDevice},
        ioctx,
        test_util::SimpleSim,
    };

    use super::*;

    const PROTO_A: u8 = 83;
    const PROTO_B: u8 = 84;

    #[test]
    #[serial]
    fn send_raw_packets() -> Result<(), RuntimeError> {
        let mut sim = SimpleSim::default();

        let v4_counter = Arc::new(AtomicUsize::new(0));
        let v6_counter = Arc::new(AtomicUsize::new(0));

        let v4_counter_c = v4_counter.clone();
        let v6_counter_c = v6_counter.clone();

        let v4_counter_f = v4_counter.clone();
        let v6_counter_f = v6_counter.clone();

        // Emitter
        sim.raw("emitter", move |_| {
            let v4_counter = v4_counter.clone();
            let v6_counter = v6_counter.clone();

            async move {
                ioctx().add_interface(
                    InterfaceDef::new("en0", NetworkDevice::eth())
                        .ip(Ipv4Addr::new(192, 168, 0, 103).into())
                        .ip(Ipv4Addr::new(255, 255, 255, 0).into())
                        .ip("fe80::02".parse::<IpAddr>().unwrap()),
                )?;

                let sockv4 = RawIpSocket::new_v4()?;
                sockv4.bind_proto(PROTO_A)?;
                let sockv6 = RawIpSocket::new_v6()?;
                sockv6.bind_proto(PROTO_A)?;

                for i in 1..10 {
                    sleep(Duration::from_secs(1)).await;
                    let v4 = random::<bool>();
                    if v4 {
                        let pkt = Ipv4Packet {
                            dscp: 0,
                            enc: 0,
                            identification: i,
                            flags: Ipv4Flags {
                                df: false,
                                mf: false,
                            },
                            fragment_offset: 0,
                            ttl: 64,
                            proto: PROTO_A,
                            src: Ipv4Addr::new(192, 168, 0, 103),
                            dst: Ipv4Addr::new(192, 168, 0, 1),
                            content: std::iter::repeat_with(|| random::<u8>()).take(16).collect(),
                        };
                        tracing::info!("v4::sending {:?}", pkt.content);
                        sockv4.try_send(IpPacket::V4(pkt)).unwrap();
                        v4_counter.fetch_add(1, Ordering::SeqCst);
                    } else {
                        let pkt = Ipv6Packet {
                            traffic_class: 0,
                            flow_label: i as u32,
                            proto: PROTO_A,
                            hop_limit: 64,
                            extension_headers: Vec::new(),
                            src: "fe80::02".parse::<Ipv6Addr>().unwrap(),
                            dst: "fe80::01".parse::<Ipv6Addr>().unwrap(),
                            content: std::iter::repeat_with(|| random::<u8>()).take(16).collect(),
                        };
                        tracing::info!("v6::sending {:?}", pkt.content);
                        sockv6.try_send(IpPacket::V6(pkt)).unwrap();
                        v6_counter.fetch_add(1, Ordering::SeqCst);
                    }
                }

                Ok(())
            }
        });

        sim.raw("receiver", move |_| {
            let v4_counter = v4_counter_c.clone();
            let v6_counter = v6_counter_c.clone();

            async move {
                ioctx().add_interface(
                    InterfaceDef::new("en0", NetworkDevice::eth())
                        .ip(Ipv4Addr::new(192, 168, 0, 1).into())
                        .ip(Ipv4Addr::new(255, 255, 255, 0).into())
                        .ip("fe80::01".parse::<IpAddr>().unwrap()),
                )?;

                spawn(async move {
                    let mut sock = RawIpSocket::new_v4().unwrap();
                    sock.bind_proto(PROTO_A).unwrap();
                    while let Ok((_, pkt)) = sock.recv().await {
                        tracing::info!("v4::received {:?}", pkt.content());
                        v4_counter.fetch_sub(1, Ordering::SeqCst);
                    }
                });
                spawn(async move {
                    let mut sock = RawIpSocket::new_v6().unwrap();
                    sock.bind_proto(PROTO_A).unwrap();
                    while let Ok((_, pkt)) = sock.recv().await {
                        tracing::info!("v6::received {:?}", pkt.content());
                        v6_counter.fetch_sub(1, Ordering::SeqCst);
                    }
                });

                Ok(())
            }
        });

        sim.run()?;

        assert_eq!(v4_counter_f.load(Ordering::SeqCst), 0);
        assert_eq!(v6_counter_f.load(Ordering::SeqCst), 0);

        Ok(())
    }

    #[test]
    #[serial]
    fn bind_unbind() -> Result<(), RuntimeError> {
        let mut sim = SimpleSim::default();
        sim.node_require_join("192.168.2.101", || async move {
            let mut socket = RawIpSocket::new_v4()?;
            socket.bind_proto(PROTO_A)?;

            let err = socket.unbind_proto(PROTO_B).unwrap_err();
            assert_eq!(err.to_string(), "binding does not exist");

            socket.unbind_proto(PROTO_A)?;
            socket.bind_proto(PROTO_B)?;

            let (id, pkt) = socket.recv().await?;
            assert_eq!(id, "en0");
            assert_eq!(pkt.content(), &[PROTO_B]);

            Ok(())
        });

        sim.node_require_join("sender", || async move {
            let socket = RawIpSocket::new_v4()?;
            for proto in [PROTO_A, PROTO_B] {
                socket.try_send(IpPacket::V4(Ipv4Packet {
                    dscp: 0,
                    enc: 0,
                    identification: 0,
                    flags: Ipv4Flags {
                        df: true,
                        mf: false,
                    },
                    fragment_offset: 0,
                    ttl: 64,
                    proto: proto,
                    src: Ipv4Addr::UNSPECIFIED,
                    dst: Ipv4Addr::new(192, 168, 2, 101),
                    content: Bytes::copy_from_slice(&[proto]),
                }))?;
            }
            Ok(())
        });

        sim.node_require_join("double-bind", || async move {
            let mut sock1 = RawIpSocket::new_v4()?;
            sock1.bind_proto(PROTO_A)?;
            let sock2 = RawIpSocket::new_v4()?;
            let err = sock2.bind_proto(PROTO_A).unwrap_err();
            assert_eq!(err.to_string(), "filter already occupied");

            let err = sock1.try_recv().unwrap_err();
            assert_eq!(err.kind(), ErrorKind::WouldBlock);

            drop((sock1, sock2));
            Ok(())
        });

        sim.node_require_join("bind-unsupported-addr", || async move {
            let err = RawIpSocket::new_v6().unwrap_err();
            assert_eq!(err.to_string(), "address not available");
            Ok(())
        });

        sim.run()
    }
}
