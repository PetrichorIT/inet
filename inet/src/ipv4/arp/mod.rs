//! The Address Resoloution Protocol (ARP)
//!
//! ARP is used to resolve IP addresses to corresponding MAC
//! addresses of hosts. Note that for simplicities sake
//! Ipv6-over-ARP is temporarily allowed.
//!
//! The user may interact with the ARP deamon by either
//! requesting the all `ArpEntry` using `arpa`.
//! The functions `set_arp_entry` defines a
//! non-expiring ARP entry to prevent jitter through
//! ARP lookups. The function `set_arp_config` can be
//! used to configure the ARP table.
//!

use std::io::{self, Error, ErrorKind};
use std::net::Ipv4Addr;

use crate::ctx::LinkLayerResult;
use crate::{IOContext, interface::*};
use des::prelude::{Message, schedule_in};
use des::time::SimTime;
use types::arp::{ARPOperation, ArpPacket, KIND_ARP};
use types::iface::MacAddress;
use types::ip::Ipv4Packet;

mod table;
pub use self::table::*;

mod api;
pub use self::api::*;

impl IOContext {
    pub fn recv_arp(&mut self, ifid: IfId, msg: &Message, arp: &ArpPacket) -> LinkLayerResult {
        use LinkLayerResult::*;
        // assert_eq!(arp.ptype, 0x0800);
        assert_eq!(arp.htype, 1);

        // tracing::debug!("{ifid} {arp:?}");

        match arp.operation {
            ARPOperation::Request => {
                assert!(MacAddress::from(msg.dst).is_broadcast());
                assert!(arp.dst_mac_addr().is_unspecified());

                // (0) Add sender entry to local arp table
                if !arp.src_ip_addr().is_unspecified() {
                    let sendable = self.ipv4.arp.update(ArpEntryInternal {
                        negated: false,
                        hostname: None,
                        ip: arp.src_ipv4_addr(),
                        mac: arp.src_mac_addr(),
                        iface: Some(ifid),
                        expires: SimTime::ZERO,
                    });

                    if let Some((trg, sendable)) = sendable {
                        tracing::trace!(
                            "learned arp resolution currently requested, sending {}",
                            sendable.len()
                        );
                        for pkt in sendable {
                            self.ipv4_send_lan_local(ifid, trg, pkt).unwrap();
                        }
                    };
                }

                // (1) check whether the responding interface has an appropiate ip addr.
                let iface = self.ifaces.get_mut(&ifid).unwrap();
                let requested_addr = arp.dst_ipv4_addr();

                let valid_iaddr = iface
                    .bindings
                    .v4
                    .unicast
                    .iter()
                    .find(|iaddr| iaddr.matches(requested_addr));

                if let Some(iaddr) = valid_iaddr {
                    let addr: Ipv4Addr = iaddr.addr;

                    assert_eq!(addr, requested_addr);

                    tracing::trace!(
                        "responding to arp request for {} with {}",
                        arp.dst_ip_addr(),
                        iface.device.addr
                    );

                    let response = arp.into_response(iface.device.addr);

                    let msg = Message::default()
                        .with_kind(KIND_ARP)
                        .with_src(iface.device.addr.into())
                        .with_dst(arp.src_mac_addr().into())
                        .with_content(response);

                    iface.send_buffered(msg).unwrap();
                }

                Consumed()
            }
            ARPOperation::Response => {
                // (0) Add response data to ARP table (not requester, was allready added)
                if !arp.dst_ip_addr().is_unspecified() {
                    let sendable = self.ipv4.arp.update(ArpEntryInternal {
                        negated: false,
                        hostname: None,
                        ip: arp.dst_ipv4_addr(),
                        mac: arp.dst_mac_addr(),
                        iface: Some(ifid),
                        expires: SimTime::ZERO,
                    });

                    tracing::trace!(
                        "receiving arp response for {} is {} (sending {})",
                        arp.dst_ip_addr(),
                        arp.dst_mac_addr(),
                        sendable.as_ref().map(|v| v.1.len()).unwrap_or(0)
                    );

                    let Some((trg, sendable)) = sendable else {
                        return Consumed();
                    };

                    for pkt in sendable {
                        self.ipv4_send_lan_local(ifid, trg, pkt).unwrap();
                    }
                }
                Consumed()
            }
        }
    }

    pub fn recv_arp_wakeup(&mut self) {
        self.ipv4.arp.active_wakeup = false;

        // (0) Collect retry info
        for addr in self.ipv4.arp.requests.keys().copied().collect::<Vec<_>>() {
            let req = self.ipv4.arp.requests.get_mut(&addr).unwrap();
            if req.deadline <= SimTime::now() {
                // retry
                if req.itr >= 1 {
                    let rem = self
                        .ipv4
                        .arp
                        .update(ArpEntryInternal {
                            negated: true,
                            hostname: None,
                            ip: addr,
                            mac: MacAddress::NULL,
                            iface: None,
                            expires: SimTime::now() + self.ipv4.arp.config.validity / 4,
                        })
                        .unwrap_or((addr, Vec::new()));

                    for pkt in rem.1 {
                        self.ipv4_icmp_routing_failed(
                            Error::new(ErrorKind::NotConnected, "Host unreachable"),
                            &pkt,
                        );
                    }

                    tracing::error!("could not resolve for {addr} dropping packets");
                    self.ipv4.arp.requests.remove(&addr);
                } else {
                    req.deadline = SimTime::now() + self.ipv4.arp.config.timeout;
                    req.itr += 1;
                    let dst = req.buffer[0].dst;
                    let id = req.iface;
                    self.arp_send_request(id, dst).unwrap();
                }
            }
        }

        if !self.ipv4.arp.requests.is_empty() {
            schedule_in(
                Message::default()
                    .with_kind(KIND_IO_TIMEOUT)
                    .with_id(KIND_ARP),
                self.ipv4.arp.config.timeout,
            );
            self.ipv4.arp.active_wakeup = true;
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

    pub fn arp_lookup(
        &self,
        dst: Ipv4Addr,
        preferred_iface: IfId,
    ) -> Option<(bool, MacAddress, IfId)> {
        self.ipv4
            .arp
            .lookup(&dst)
            .map(|e| (e.negated, e.mac, e.iface.unwrap()))
            .or_else(|| {
                let iface = self.ifaces.get(&preferred_iface)?;
                let looback = iface.flags.loopback && dst.is_loopback();
                let self_addr = iface.bindings.v4.matches(dst);
                if looback || self_addr {
                    Some((false, iface.device.addr, iface.name.id()))
                } else {
                    None
                }
            })
        // .map(|(addr, ifid)| (addr, self.map_to_valid_ifid(ifid)))
    }

    pub fn arp_missing_addr_mapping(
        &mut self,
        ifid: IfId,
        pkt: Ipv4Packet,
        dst: Ipv4Addr,
    ) -> io::Result<()> {
        let active_lookup = self.ipv4.arp.active_lookup(&dst);
        self.ipv4.arp.enqueue(pkt, dst, ifid);

        if active_lookup {
            return Ok(());
        }

        self.arp_send_request(ifid, dst)
    }

    pub fn arp_send_request(&mut self, ifid: IfId, dst: Ipv4Addr) -> io::Result<()> {
        let mut iface = self.ifaces.get_mut(&ifid).unwrap();
        if iface.flags.loopback && !dst.is_loopback() {
            let name = iface.name.clone();
            let Some(eth) = self.ifaces.values_mut().find(|iface| !iface.flags.loopback) else {
                panic!()
            };
            tracing::trace!(
                "redirecting ARP request to new interface {} (socket operates on {})",
                eth.name,
                name
            );
            // ifid = *eth.0;
            iface = eth;
        }

        self.ipv4.arp.requests.get_mut(&dst).unwrap().iface = iface.name.id();

        tracing::trace!(
            "missing address resolution for {}, initiating ARP request at {}",
            dst,
            iface.name
        );

        let request = ArpPacket::new_v4_request(
            iface.device.addr,
            iface
                .ipv4_subnet()
                .map(|v| v.0)
                .unwrap_or(Ipv4Addr::UNSPECIFIED),
            dst,
        );

        let msg = Message::default()
            .with_kind(KIND_ARP)
            .with_src(iface.device.addr.into())
            .with_dst(MacAddress::BROADCAST.into())
            .with_content(request);

        if !self.ipv4.arp.active_wakeup {
            self.ipv4.arp.active_wakeup = true;
            schedule_in(
                Message::default()
                    .with_kind(KIND_IO_TIMEOUT)
                    .with_id(KIND_ARP),
                self.ipv4.arp.config.timeout,
            );
        }

        iface.send_buffered(msg).expect("failed to send ARP packet");
        Ok(())
    }
}
