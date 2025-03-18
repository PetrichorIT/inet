use std::{
    io::{self, Error, ErrorKind},
    net::Ipv4Addr,
};

use arp::ArpTable;
use des::prelude::Message;
use icmp::Icmp;
use router::{FwdV4, Ipv4Gateway};
use types::{
    icmpv4::PROTO_ICMPV4,
    iface::MacAddress,
    ip::{IpPacket, Ipv4Packet, KIND_IPV4},
};

use crate::{ctx::NetworkLayerResult, interface::IfId, socket::SocketIfaceBinding, IOContext};

pub mod arp;
pub mod icmp;
pub mod router;

#[derive(Debug)]
pub(super) struct Ipv4 {
    pub arp: ArpTable,
    pub icmp: Icmp,
    pub fwd: FwdV4,
}

impl Default for Ipv4 {
    fn default() -> Self {
        Self {
            arp: ArpTable::new(),
            icmp: Icmp::new(),
            fwd: FwdV4::new(),
        }
    }
}

impl IOContext {
    pub fn ipv4_recv(&mut self, msg: Message, ifid: IfId) -> NetworkLayerResult {
        let Ok((pkt, header)) = msg.try_cast::<Ipv4Packet>() else {
            tracing::error!(
                "received eth-packet with kind=0x0800 (ip) but content was no ipv4-packet"
            );
            return NetworkLayerResult::Consumed();
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
                self.icmp_ttl_expired(ifid, &pkt);
                return NetworkLayerResult::Consumed();
            }

            tracing::debug!("fwd packet to {}", pkt.dst);

            if let Err(error) = self.send_ip_packet(
                SocketIfaceBinding::Any(self.ifaces.keys().cloned().collect()),
                IpPacket::V4(pkt.clone()), // TODO: to not copy, use a result Err(Packet)
                true,
            ) {
                tracing::error!("failed to forward ip-packet {error}");
                self.icmp_routing_failed(error, &pkt);
            }

            return NetworkLayerResult::Consumed();
        }

        match pkt.proto {
            PROTO_ICMPV4 => {
                let _consumed = self.recv_icmpv4_packet(&pkt, ifid);
                NetworkLayerResult::Consumed()
            }
            0 => NetworkLayerResult::PassThrough(Message::from_parts(header, Some(pkt))),
            _ => NetworkLayerResult::TransportLayerPacket(IpPacket::V4(pkt), header),
        }
    }
}

impl IOContext {
    pub fn send_ip_packet(
        &mut self,
        ifid: SocketIfaceBinding,
        pkt: IpPacket,
        buffered: bool,
    ) -> io::Result<()> {
        if let IpPacket::V6(pkt) = pkt {
            return self.ipv6_send(pkt, ifid.unwrap_ifid());
        }

        match pkt {
            IpPacket::V4(pkt) => self.send_ip_packet_v4(ifid, pkt, buffered),
            IpPacket::V6(pkt) => self.ipv6_send(pkt, ifid.unwrap_ifid()),
        }
    }

    pub fn send_ip_packet_v4(
        &mut self,
        ifid: SocketIfaceBinding,
        pkt: Ipv4Packet,
        buffered: bool,
    ) -> io::Result<()> {
        // (0) Routing table destintation lookup

        let Some((route, rifid)) = self.ipv4.fwd.lookup(pkt.dst) else {
            return Err(Error::new(
                ErrorKind::ConnectionRefused,
                "no gateway network reachable",
            ));
        };

        match route {
            Ipv4Gateway::Local => self.ipv4_send_lan_local(
                SocketIfaceBinding::Bound(rifid.id()),
                pkt.dst,
                pkt,
                buffered,
            ),
            Ipv4Gateway::Gateway(gw) => {
                self.ipv4_send_lan_local(SocketIfaceBinding::Bound(rifid.id()), *gw, pkt, buffered)
            }
            // TODO: move logic to extra, non-arp fn
            Ipv4Gateway::Broadcast => self.ipv4_broadcast(ifid, pkt, buffered),
        }
    }

    pub fn ipv4_broadcast(
        &mut self,
        ifid: SocketIfaceBinding,
        pkt: Ipv4Packet,
        buffered: bool,
    ) -> io::Result<()> {
        // Since we are broadcasting, use ff
        match ifid {
            SocketIfaceBinding::Bound(_) => self.ipv4_send_lan_local(ifid, pkt.dst, pkt, buffered),
            _ => {
                for (_ifid, iface) in &mut self.ifaces {
                    let mut pkt = pkt.clone();
                    if pkt.src.is_unspecified() {
                        pkt.src = iface.ipv4_subnet().unwrap().0;
                    }
                    let msg = Message::new()
                        .kind(KIND_IPV4)
                        .src(iface.device.addr.into())
                        .dest(MacAddress::BROADCAST.into())
                        .content(pkt)
                        .build();

                    if buffered {
                        iface.send_buffered(msg)?;
                    } else {
                        iface.send(msg)?;
                    }
                }
                Ok(())
            }
        }
    }

    fn ipv4_send_lan_local(
        &mut self,
        ifid: SocketIfaceBinding,
        dst: Ipv4Addr,
        pkt: Ipv4Packet,
        buffered: bool,
    ) -> io::Result<()> {
        let Some((negated, mac, ifid)) = self.arp_lookup(dst, &ifid) else {
            self.arp_missing_addr_mapping(ifid, pkt, dst)?;
            return Ok(());
        };

        if negated {
            return Err(Error::new(ErrorKind::NotConnected, "Host unreachable"));
        }

        let Some(iface) = self.ifaces.get_mut(&ifid) else {
            return Err(Error::new(
                ErrorKind::Other,
                "interface does not exist anymore",
            ));
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
        let msg = Message::new()
            .kind(KIND_IPV4)
            .src(iface.device.addr.into())
            .dest(mac.into())
            .content(pkt)
            .build();

        if buffered {
            iface.send_buffered(msg)
        } else {
            iface.send(msg)
        }
    }
}
