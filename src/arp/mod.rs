use std::io::{self, Error, ErrorKind};
use std::net::{IpAddr, Ipv4Addr};

use crate::ip::{IpPacket, Ipv4Packet, KIND_IPV4};
use crate::routing::Ipv4Gateway;
use crate::socket::SocketIfaceBinding;
use crate::{interface::*, IOContext};
use des::prelude::Message;
use des::time::SimTime;

mod pkt;
pub use self::pkt::*;

mod table;
pub use self::table::*;

mod api;
pub use self::api::*;

impl IOContext {
    pub fn recv_arp(&mut self, ifid: IfId, msg: &Message, arp: &ARPPacket) -> LinkLayerResult {
        use LinkLayerResult::*;
        match arp.operation {
            ARPOperation::Request => {
                assert!(MacAddress::from(msg.header().dest).is_broadcast());
                assert!(arp.dest_haddr.is_unspecified());

                // (0) Add sender entry to local arp table
                if !arp.src_paddr.is_unspecified() {
                    // log::trace!(target: "inet/arp", "receiving arp request for {}", arp.dest_paddr);
                    let sendable = self.arp.add(ARPEntryInternal {
                        hostname: None,
                        ip: arp.src_paddr,
                        mac: arp.src_haddr,
                        iface: ifid,
                        expires: SimTime::ZERO,
                    });

                    if let Some((trg, sendable)) = sendable {
                        for pkt in sendable {
                            self.send_lan_local_ipv4_packet(
                                SocketIfaceBinding::Bound(ifid),
                                trg,
                                pkt,
                                true,
                            )
                            .unwrap();
                        }
                    };
                }

                // (1) check whether the responding interface has an appropiate ip addr.
                let iface = self.ifaces.get_mut(&ifid).unwrap();
                let addr = arp.dest_paddr;

                let valid_iaddr = iface
                    .addrs
                    .iter()
                    .find(|iaddr| iaddr.matches_ip(IpAddr::V4(addr)));

                if let Some(iaddr) = valid_iaddr {
                    let InterfaceAddr::Inet { addr, .. } = iaddr else {
                        unreachable!()
                    };

                    log::trace!(target: "inet/arp", "responding to arp request for {} with {}", arp.dest_paddr, iface.device.addr);

                    let response = ARPPacket {
                        htype: 1,
                        ptype: 0x0800,
                        operation: ARPOperation::Response,
                        src_haddr: arp.src_haddr,
                        src_paddr: arp.src_paddr,
                        dest_haddr: iface.device.addr,
                        dest_paddr: *addr,
                    };

                    let msg = Message::new()
                        .kind(KIND_ARP)
                        .src(iface.device.addr.into())
                        .dest(arp.src_haddr.into())
                        .content(response)
                        .build();

                    iface.send_buffered(msg).unwrap();
                }

                Consumed()
            }
            ARPOperation::Response => {
                // (0) Add response data to ARP table (not requester, was allready added)
                if !arp.dest_paddr.is_unspecified() {
                    let sendable = self.arp.add(ARPEntryInternal {
                        hostname: None,
                        ip: arp.dest_paddr,
                        mac: arp.dest_haddr,
                        iface: ifid,
                        expires: SimTime::ZERO,
                    });

                    log::trace!(
                        target: "inet/arp",
                        "receiving arp response for {} is {} (sending {})",
                        arp.dest_paddr,
                        arp.dest_haddr,
                        sendable.as_ref().map(|v| v.1.len()).unwrap_or(0)
                    );

                    let Some((trg, sendable)) = sendable else {
                        return Consumed();
                    };

                    for pkt in sendable {
                        self.send_lan_local_ipv4_packet(
                            SocketIfaceBinding::Bound(ifid),
                            trg,
                            pkt,
                            true,
                        )
                        .unwrap();
                    }
                }
                Consumed()
            }
        }
    }

    pub fn send_ip_packet(&mut self, ifid: SocketIfaceBinding, pkt: IpPacket) -> io::Result<()> {
        match pkt {
            IpPacket::V4(v4) => self.send_ipv4_packet(ifid, v4, false),
            _ => Ok(()),
        }
    }

    pub fn send_ipv4_packet(
        &mut self,
        ifid: SocketIfaceBinding,
        pkt: Ipv4Packet,
        buffered: bool,
    ) -> io::Result<()> {
        for line in self.route() {
            log::debug!("{line:?}")
        }

        // (0) Routing table destintation lookup
        let Some((route, rifid)) = self.ipv4router.loopuk_gateway(pkt.dest) else {
            return Err(Error::new(
                ErrorKind::Other,
                "no gateway network reachable"
            ))
        };

        log::info!("r: {route:?} via {}", self.ifaces.get(&rifid).unwrap().name);

        match route {
            Ipv4Gateway::Local => self.send_lan_local_ipv4_packet(
                SocketIfaceBinding::Bound(*rifid),
                pkt.dest,
                pkt,
                buffered,
            ),
            Ipv4Gateway::Gateway(gw) => self.send_lan_local_ipv4_packet(
                SocketIfaceBinding::Bound(*rifid),
                *gw,
                pkt,
                buffered,
            ),
            // TODO: move logic to extra, non-arp fn
            Ipv4Gateway::Broadcast => {
                self.send_lan_local_ipv4_packet(ifid, pkt.dest, pkt, buffered)
            }
        }
    }

    // pub fn send_gateway_ipv4_packet(
    //     &mut self,
    //     ifid: IfId,
    //     mut pkt: Ipv4Packet,
    //     gateway: Ipv4Addr,
    //     buffered: bool,
    // ) -> io::Result<()> {
    //     Ok(())
    // }

    pub fn send_lan_local_ipv4_packet(
        &mut self,
        ifid: SocketIfaceBinding,
        dest: Ipv4Addr,
        mut pkt: Ipv4Packet,
        buffered: bool,
    ) -> io::Result<()> {
        let Some((mac, ifid)) = self.arp_lookup_for_ipv4(&dest, &ifid) else {
            self.arp_missing_addr_mapping(ifid, pkt, dest)?;
            return Ok(())
        };

        let Some(iface) = self.ifaces.get_mut(&ifid) else {
            return Err(Error::new(
                ErrorKind::Other,
                "interface does not exist anymore"
            ));
        };

        if mac == MacAddress::BROADCAST && !iface.flags.broadcast {
            return Err(Error::new(
                ErrorKind::AddrNotAvailable,
                "cannot send broadcast packet on non-broadcast interface",
            ));
        }

        pkt.src = iface.ipv4_subnet().unwrap().0;

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

    fn arp_lookup_for_ipv4(
        &self,
        dest: &Ipv4Addr,
        preferred_iface: &SocketIfaceBinding,
    ) -> Option<(MacAddress, IfId)> {
        self.arp
            .lookup(dest)
            .map(|e| (e.mac, e.iface))
            .or_else(|| match preferred_iface {
                SocketIfaceBinding::Bound(ifid) => {
                    let Some(iface) = self.ifaces.get(&ifid) else {
                        return None;
                    };
                    let looback = iface.flags.loopback && dest.is_loopback();
                    let self_addr = iface
                        .addrs
                        .iter()
                        .any(|addr| addr.matches_ip(IpAddr::V4(*dest)));
                    if looback || self_addr {
                        Some((iface.device.addr, iface.name.id))
                    } else {
                        None
                    }
                }
                SocketIfaceBinding::Any(ifids) => {
                    for ifid in ifids {
                        let Some(iface) = self.ifaces.get(&ifid) else {
                            continue;
                        };
                        let looback = iface.flags.loopback && dest.is_loopback();
                        let self_addr = iface
                            .addrs
                            .iter()
                            .any(|addr| addr.matches_ip(IpAddr::V4(*dest)));
                        if looback || self_addr {
                            return Some((iface.device.addr, iface.name.id));
                        }
                    }
                    None
                }

                _ => panic!("not yet implemented: {} {:?}", dest, preferred_iface),
            })
        // .map(|(addr, ifid)| (addr, self.map_to_valid_ifid(ifid)))
    }

    fn arp_missing_addr_mapping(
        &mut self,
        ifid: SocketIfaceBinding,
        pkt: Ipv4Packet,
        dest: Ipv4Addr,
    ) -> io::Result<()> {
        let active_lookup = self.arp.active_lookup(&dest);
        self.arp.wait_for_arp(pkt, dest);

        if active_lookup {
            return Ok(());
        }

        let iface = match ifid {
            SocketIfaceBinding::Bound(ifid) => {
                let mut iface = self.ifaces.get_mut(&ifid).unwrap();
                if iface.flags.loopback && !dest.is_loopback() {
                    let name = iface.name.clone();
                    let Some(eth) = self.ifaces.iter_mut().find(|(_, iface)| !iface.flags.loopback) else {
                        panic!()
                    };
                    log::trace!(target: "inet/arp", "redirecting ARP request to new interface {} (socket operates on {})", eth.1.name, name);
                    // ifid = *eth.0;
                    iface = eth.1;
                }
                iface
            }
            SocketIfaceBinding::Any(ifids) => {
                let mut iface = self.ifaces.get_mut(&ifids[0]).unwrap();
                if iface.flags.loopback && !dest.is_loopback() {
                    let name = iface.name.clone();
                    let Some(eth) = self.ifaces.iter_mut().find(|(_, iface)| !iface.flags.loopback) else {
                            panic!()
                        };
                    log::trace!(target: "inet/arp", "redirecting ARP request to new interface {} (socket operates on {})", eth.1.name, name);
                    // ifid = *eth.0;
                    iface = eth.1;
                }
                iface
            }
            SocketIfaceBinding::NotBound => {
                return Err(Error::new(ErrorKind::Other, "socket bound to no interface"))
            }
        };

        log::trace!(target: "inet/arp", "missing address resolution for {}, initiating ARP request at {}", dest, iface.name);

        let request = ARPPacket {
            htype: 1,
            ptype: 0x0800,
            operation: ARPOperation::Request,
            src_haddr: iface.device.addr,
            src_paddr: iface
                .ipv4_subnet()
                .map(|v| v.0)
                .unwrap_or(Ipv4Addr::UNSPECIFIED),
            dest_haddr: MacAddress::NULL,
            dest_paddr: dest,
        };

        let msg = Message::new()
            .kind(KIND_ARP)
            .src(iface.device.addr.into())
            .dest(MacAddress::BROADCAST.into())
            .content(request)
            .build();

        iface.send_buffered(msg)
    }
}
