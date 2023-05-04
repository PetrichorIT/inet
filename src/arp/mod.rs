use std::io::{self, Error, ErrorKind};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::routing::IpGateway;
use crate::socket::SocketIfaceBinding;
use crate::{interface::*, IOContext};
use des::prelude::Message;
use des::time::SimTime;
use inet_types::ip::{IpPacket, KIND_IPV4, KIND_IPV6};

mod pkt;
pub use self::pkt::*;

mod table;
pub use self::table::*;

mod api;
pub use self::api::*;

impl IOContext {
    pub fn recv_arp(&mut self, ifid: IfId, msg: &Message, arp: &ArpPacket) -> LinkLayerResult {
        use LinkLayerResult::*;
        // assert_eq!(arp.ptype, 0x0800);
        assert_eq!(arp.htype, 1);

        // log::debug!("{ifid} {arp:?}");

        match arp.operation {
            ARPOperation::Request => {
                assert!(MacAddress::from(msg.header().dest).is_broadcast());
                assert!(arp.dest_mac_addr().is_unspecified());

                // (0) Add sender entry to local arp table
                if !arp.src_ip_addr().is_unspecified() {
                    // log::trace!(target: "inet/arp", "receiving arp request for {}", arp.dest_paddr);
                    let sendable = self.arp.update(ArpEntryInternal {
                        hostname: None,
                        ip: arp.src_ip_addr().into(),
                        mac: arp.src_mac_addr(),
                        iface: ifid,
                        expires: SimTime::ZERO,
                    });

                    if let Some((trg, sendable)) = sendable {
                        for pkt in sendable {
                            self.send_lan_local_ip_packet(
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
                let requested_addr = arp.dest_ip_addr();

                let valid_iaddr = iface
                    .addrs
                    .iter()
                    .find(|iaddr| iaddr.matches_ip(requested_addr));

                if let Some(iaddr) = valid_iaddr {
                    let addr: IpAddr = match iaddr {
                        InterfaceAddr::Inet { addr, .. } => (*addr).into(),
                        InterfaceAddr::Inet6 { addr, .. } => (*addr).into(),
                        _ => unreachable!(),
                    };

                    assert_eq!(addr, requested_addr);

                    log::trace!(target: "inet/arp", "responding to arp request for {} with {}", arp.dest_ip_addr(), iface.device.addr);

                    let response = arp.into_response(iface.device.addr);

                    let msg = Message::new()
                        .kind(KIND_ARP)
                        .src(iface.device.addr.into())
                        .dest(arp.src_mac_addr().into())
                        .content(response)
                        .build();

                    self.pcap.borrow_mut().capture(&msg, ifid, iface).unwrap();
                    iface.send_buffered(msg).unwrap();
                }

                Consumed()
            }
            ARPOperation::Response => {
                // (0) Add response data to ARP table (not requester, was allready added)
                if !arp.dest_ip_addr().is_unspecified() {
                    let sendable = self.arp.update(ArpEntryInternal {
                        hostname: None,
                        ip: arp.dest_ip_addr().into(),
                        mac: arp.dest_mac_addr(),
                        iface: ifid,
                        expires: SimTime::ZERO,
                    });

                    log::trace!(
                        target: "inet/arp",
                        "receiving arp response for {} is {} (sending {})",
                        arp.dest_ip_addr(),
                        arp.dest_mac_addr(),
                        sendable.as_ref().map(|v| v.1.len()).unwrap_or(0)
                    );

                    let Some((trg, sendable)) = sendable else {
                        return Consumed();
                    };

                    for pkt in sendable {
                        self.send_lan_local_ip_packet(
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

    // # Ipv4 sending schedule
    //
    // (0) Input
    //     - a packet to be send to, and an indication whether buffering should be allowed
    //     - A binding of the socket, used as a fallback iface if no meaningful route was found
    // (1) Route lookup
    //     - Using the appropiate routing table, find a entry with the greatest matching prefix
    //     - If not route was found, thus no gateway defined, return an error
    //     - Routes may be:
    //       - local, thus the packet should be send to the destination directly
    //       - nonlocal/gateway, thus a gateway points to a valid dest-subnet
    //       - broadcast
    //     - returns a gatway and an associated IfId
    // (2a) If the packet is local, send it to the interface to be send onto the local subnet.
    // (2b) If the packet is nonlocal, use the gateway do define the next hop for the packet, and send it to the gateway.
    // (3) To send a packet, the system may buffer the packet and initiate a ARP request to find the next hop.
    // (4) Send the packet with the appropriate MAC address

    pub fn send_ip_packet(
        &mut self,
        ifid: SocketIfaceBinding,
        pkt: IpPacket,
        buffered: bool,
    ) -> io::Result<()> {
        // (0) Routing table destintation lookup

        let (route, rifid): (IpGateway, IfId) = match &pkt {
            IpPacket::V4(pkt) => {
                let Some((route, rifid)) = self.ipv4router.loopuk_gateway(pkt.dest) else {
                    return Err(Error::new(
                        ErrorKind::Other,
                        "no gateway network reachable"
                    ))
                };
                (route.clone().into(), *rifid)
            }
            IpPacket::V6(pkt) => {
                let Some((route, rifid)) = self.ipv6router.loopuk_gateway(pkt.dest) else {
                return Err(Error::new(
                    ErrorKind::Other,
                    "no gateway network reachable"
                ))
            };
                (route.clone().into(), *rifid)
            }
        };

        match route {
            IpGateway::Local => self.send_lan_local_ip_packet(
                SocketIfaceBinding::Bound(rifid),
                pkt.dest(),
                pkt,
                buffered,
            ),
            IpGateway::Gateway(gw) => {
                self.send_lan_local_ip_packet(SocketIfaceBinding::Bound(rifid), gw, pkt, buffered)
            }
            // TODO: move logic to extra, non-arp fn
            IpGateway::Broadcast => self.send_lan_local_ip_packet(ifid, pkt.dest(), pkt, buffered),
        }
    }

    pub fn send_lan_local_ip_packet(
        &mut self,
        ifid: SocketIfaceBinding,
        dest: IpAddr,
        pkt: IpPacket,
        buffered: bool,
    ) -> io::Result<()> {
        let Some((mac, ifid)) = self.arp_lookup(dest, &ifid) else {
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

        match pkt {
            IpPacket::V4(mut pkt) => {
                if pkt.src.is_unspecified() {
                    pkt.src = iface.ipv4_subnet().unwrap().0;
                }
                let msg = Message::new()
                    .kind(KIND_IPV4)
                    .src(iface.device.addr.into())
                    .dest(mac.into())
                    .content(pkt)
                    .build();

                self.pcap.borrow_mut().capture(&msg, ifid, iface).unwrap();
                if buffered {
                    iface.send_buffered(msg)
                } else {
                    iface.send(msg)
                }
            }
            IpPacket::V6(mut pkt) => {
                if pkt.src.is_unspecified() {
                    pkt.src = iface.ipv6_subnet().unwrap().0;
                }
                let msg = Message::new()
                    .kind(KIND_IPV6)
                    .src(iface.device.addr.into())
                    .dest(mac.into())
                    .content(pkt)
                    .build();

                self.pcap.borrow_mut().capture(&msg, ifid, iface).unwrap();
                if buffered {
                    iface.send_buffered(msg)
                } else {
                    iface.send(msg)
                }
            }
        }
    }

    fn arp_lookup(
        &self,
        dest: IpAddr,
        preferred_iface: &SocketIfaceBinding,
    ) -> Option<(MacAddress, IfId)> {
        self.arp
            .lookup(&dest)
            .map(|e| (e.mac, e.iface))
            .or_else(|| match preferred_iface {
                SocketIfaceBinding::Bound(ifid) => {
                    let Some(iface) = self.ifaces.get(&ifid) else {
                        return None;
                    };
                    let looback = iface.flags.loopback && dest.is_loopback();
                    let self_addr = iface.addrs.iter().any(|addr| addr.matches_ip(dest));
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
                        let self_addr = iface.addrs.iter().any(|addr| addr.matches_ip(dest));
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
        pkt: IpPacket,
        dest: IpAddr,
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

        let request = ArpPacket::new_request(
            iface.device.addr,
            if dest.is_ipv4() {
                iface
                    .ipv4_subnet()
                    .map(|v| v.0)
                    .unwrap_or(Ipv4Addr::UNSPECIFIED)
                    .into()
            } else {
                iface
                    .ipv6_subnet()
                    .map(|v| v.0)
                    .unwrap_or(Ipv6Addr::UNSPECIFIED)
                    .into()
            },
            dest,
        );

        let msg = Message::new()
            .kind(KIND_ARP)
            .src(iface.device.addr.into())
            .dest(MacAddress::BROADCAST.into())
            .content(request)
            .build();

        self.pcap
            .borrow_mut()
            .capture(&msg, iface.name.id, iface)
            .unwrap();
        iface.send_buffered(msg)
    }
}
