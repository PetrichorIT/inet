use std::{
    io::{self, Error, ErrorKind},
    net::Ipv4Addr,
    time::Duration,
};

use arp::ArpTable;
use des::prelude::{Message, schedule_in};
use fxhash::FxHashMap;
use router::{FwdV4, Ipv4Gateway};
use types::{
    icmpv4::PROTO_ICMPV4,
    iface::MacAddress,
    ip::{IPV4_MINIMUM_MTU, IpPacket, Ipv4Packet, KIND_IPV4},
};

use crate::{
    IOContext, IOHandle,
    ctx::NetworkLayerResult,
    interface::{IfId, IfSpec},
    ioctx,
    ipv4::socket::RawV4SocketHandle,
    socket::Fd,
};

pub mod arp;
pub mod icmp;
pub mod router;
pub mod socket;
pub mod util;

#[derive(Debug, Default)]
pub(super) struct Ipv4 {
    pub arp: ArpTable,
    pub fwd: FwdV4,
    pub cfg: HostConfiguration,
    pub sockets: FxHashMap<Fd, RawV4SocketHandle>,
}

#[derive(Debug, Default)]
pub struct HostConfiguration {
    pub no_icmp_responses: bool,
}

pub fn set_host_config(cfg: HostConfiguration) -> io::Result<()> {
    ioctx().ipv4_set_host_config(cfg)
}

impl IOHandle {
    pub fn ipv4_set_host_config(&self, cfg: HostConfiguration) -> io::Result<()> {
        self.do_failable(|ctx| {
            ctx.ipv4.cfg = cfg;
            Ok(())
        })
    }
}

impl IOContext {
    pub fn ipv4_recv(&mut self, msg: Message, ifid: IfId) -> NetworkLayerResult {
        let Ok((pkt, header, _)) = msg.try_into_content::<Ipv4Packet>() else {
            tracing::error!(
                "received eth-packet with kind=0x0800 (ip) but content was no ipv4-packet"
            );
            return NetworkLayerResult::Consumed;
        };

        let iface = self
            .ifaces
            .get(&ifid)
            .expect("interface was already resolved");

        let is_local_dest = iface.bindings.v4.matches(pkt.dst) || pkt.dst.is_broadcast();
        if !is_local_dest {
            let mut pkt = pkt;
            pkt.ttl = pkt.ttl.saturating_sub(1);

            if pkt.ttl == 0 {
                tracing::warn!("dropped ipv4-packet with ttl 0");
                let _ = self
                    .ipv4_icmp_send_ttl_expired(ifid, &pkt)
                    .inspect_err(|e| tracing::error!("icmp failed: {e}"));
                return NetworkLayerResult::Consumed;
            }

            tracing::debug!("routing packet {}->{}", pkt.src, pkt.dst);

            if let Err(error) = self.ipv4_send(
                None,
                pkt.clone(), // TODO: to not copy, use a result Err(Packet)
            ) {
                tracing::error!("failed to forward ip-packet {error}");
                self.ipv4_icmp_routing_failed(error, &pkt);
            }

            return NetworkLayerResult::Consumed;
        }

        // Recv raw sockets
        for socket in self
            .ipv4
            .sockets
            .values_mut()
            .filter(|sock| sock.proto == pkt.proto)
        {
            println!("-> fwd to raw socket {}", pkt.proto);
            socket.recv(ifid, pkt.clone());
        }

        match pkt.proto {
            PROTO_ICMPV4 => {
                let _consumed = self.ipv4_icmp_recv(&pkt, ifid);
                NetworkLayerResult::Consumed
            }
            0 => NetworkLayerResult::PassThrough(Message::from_parts(header, Some(pkt))),
            _ => NetworkLayerResult::Forward((IpPacket::V4(pkt), header)),
        }
    }
}

impl IOContext {
    pub fn ipv4_get_local_mtu(&self, dst: Ipv4Addr) -> usize {
        const DEFAULT_UNKNOWN_MTU: usize = IPV4_MINIMUM_MTU - Ipv4Packet::MIN_HEADER_SIZE;

        if dst.is_unspecified() {
            return DEFAULT_UNKNOWN_MTU;
        }

        let Some((_, ifid)) = self.ipv4.fwd.lookup(dst) else {
            return DEFAULT_UNKNOWN_MTU;
        };

        let ifid = ifid.id();
        self.ifaces.get(&ifid).map_or(DEFAULT_UNKNOWN_MTU, |iface| {
            iface.device.mtu() - Ipv4Packet::MIN_HEADER_SIZE
        })
    }

    pub fn ipv4_src_addr_for_dst(&self, dst: Ipv4Addr) -> io::Result<Ipv4Addr> {
        let Some((_, rifid)) = self.ipv4.fwd.lookup(dst) else {
            return Err(Error::new(
                ErrorKind::ConnectionRefused,
                "no gateway network reachable",
            ));
        };

        let (subnet, _mask) = self
            .ifaces
            .get(&rifid.id())
            .expect("illegal state")
            .ipv4_subnet()
            .expect("must have a subnet");

        Ok(subnet)
    }

    pub fn ipv4_send(&mut self, ifspec: IfSpec, mut pkt: Ipv4Packet) -> io::Result<()> {
        // tracing::info!("ipv4_send({}->{} on <{:?}>)", pkt.src, pkt.dst, ifspec);

        // (0) Routing table destintation lookup
        let Some((route, rifid)) = self.ipv4.fwd.lookup(pkt.dst) else {
            return Err(Error::new(
                ErrorKind::ConnectionRefused,
                "no gateway network reachable",
            ));
        };

        // Set src addr
        if !matches!(route, Ipv4Gateway::Broadcast) && pkt.src.is_unspecified() {
            let iface = self.ifaces.get(&rifid.id()).expect("illegal state");
            pkt.src = iface.ipv4_subnet().expect("illegal state").0;
            // tracing::info!("-> set pkt.src = {}", pkt.src);
        }

        // Self-Send
        if pkt.src == pkt.dst {
            // tracing::info!("-> self-send");
            let loopback = self.ifaces.values_mut().find(|iface| iface.flags.loopback);
            if let Some(loopback) = loopback {
                loopback
                    .send_buffered(Message::default().with_kind(KIND_IPV4).with_content(pkt))?;
            } else {
                // FIXME: dangerous since this execut4e directly
                let iface = self.ifaces.get(&rifid.id()).unwrap();
                schedule_in(
                    Message::default()
                        .with_last_gate(iface.device.input().unwrap())
                        .with_kind(KIND_IPV4)
                        .with_src(iface.device.addr.into())
                        .with_dst(iface.device.addr.into())
                        .with_content(pkt),
                    Duration::ZERO,
                );
            }
            return Ok(());
        }

        match route {
            Ipv4Gateway::Local => self.ipv4_send_lan_local(rifid.id(), pkt.dst, pkt),
            Ipv4Gateway::Gateway(gw) => self.ipv4_send_lan_local(rifid.id(), *gw, pkt),
            // TODO: move logic to extra, non-arp fn
            Ipv4Gateway::Broadcast => self.ipv4_broadcast(ifspec, pkt),
        }
    }

    pub fn ipv4_broadcast(&mut self, ifspec: IfSpec, pkt: Ipv4Packet) -> io::Result<()> {
        // Since we are broadcasting, use ff
        match ifspec {
            Some(id) => self.ipv4_send_lan_local(id, pkt.dst, pkt),
            _ => {
                for iface in self.ifaces.values_mut() {
                    let mut pkt = pkt.clone();
                    if pkt.src.is_unspecified() {
                        pkt.src = iface.ipv4_subnet().unwrap().0;
                    }
                    let msg = Message::default()
                        .with_kind(KIND_IPV4)
                        .with_src(iface.device.addr.into())
                        .with_dst(MacAddress::BROADCAST.into())
                        .with_content(pkt);

                    iface.send_buffered(msg)?;
                }
                Ok(())
            }
        }
    }

    fn ipv4_send_lan_local(
        &mut self,
        ifid: IfId,
        next_hop: Ipv4Addr,
        pkt: Ipv4Packet,
    ) -> io::Result<()> {
        assert!(!pkt.src.is_unspecified());

        let Some((negated, mac, ifid)) = self.arp_lookup(next_hop, ifid) else {
            self.arp_missing_addr_mapping(ifid, pkt, next_hop)?;
            return Ok(());
        };

        if negated {
            return Err(Error::new(ErrorKind::NotConnected, "Host unreachable"));
        }

        let Some(iface) = self.ifaces.get_mut(&ifid) else {
            return Err(Error::other("interface does not exist anymore"));
        };

        if mac == MacAddress::BROADCAST && !iface.flags.broadcast {
            return Err(Error::new(
                ErrorKind::AddrNotAvailable,
                "cannot send broadcast packet on non-broadcast interface",
            ));
        }

        let mut pkt = pkt.clone();
        if pkt.src.is_unspecified() {
            pkt.src = iface.ipv4_subnet().unwrap().0;
        }

        let msg = Message::default()
            .with_kind(KIND_IPV4)
            .with_src(iface.device.addr.into())
            .with_dst(mac.into())
            .with_content(pkt);

        iface.send_buffered(msg)?;

        Ok(())
    }
}
