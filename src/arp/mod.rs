use std::io::{self, Error, ErrorKind};
use std::net::{IpAddr, Ipv4Addr};

use crate::ip::{IpPacket, Ipv4Packet, KIND_IPV4};
use crate::{interface2::*, IOContext};
use des::prelude::Message;
use des::time::SimTime;

mod pkt;
pub use self::pkt::*;

mod table;
pub use self::table::*;

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
                    self.arp.add(ARPEntry {
                        hostname: None,
                        ip: arp.src_paddr,
                        mac: arp.src_haddr,
                        iface: ifid,
                        expires: SimTime::ZERO,
                    });
                }

                // (1) check whether the responding interface has an appropiate ip addr.
                let iface = self.interfaces2.get_mut(&ifid).unwrap();
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
                    log::trace!(
                        target: "inet/arp",
                        "receiving arp response for {} is {}",
                        arp.dest_paddr,
                        arp.dest_haddr
                    );

                    let sendable = self.arp.add(ARPEntry {
                        hostname: None,
                        ip: arp.dest_paddr,
                        mac: arp.dest_haddr,
                        iface: ifid,
                        expires: SimTime::ZERO,
                    });

                    let Some(sendable) = sendable else {
                        return Consumed();
                    };

                    for pkt in sendable {
                        self.send_ip_packet_v4(ifid, pkt, true).unwrap();
                    }
                }
                Consumed()
            }
        }
    }

    pub fn send_ip_packet(&mut self, ifid: IfId, pkt: IpPacket) -> io::Result<()> {
        match pkt {
            IpPacket::V4(v4) => self.send_ip_packet_v4(ifid, v4, false),
            _ => Ok(()),
        }
    }

    pub fn send_ip_packet_v4(
        &mut self,
        ifid: IfId,
        pkt: Ipv4Packet,
        buffered: bool,
    ) -> io::Result<()> {
        let Some(entry) = self.arp.lookup(&pkt.dest) else {
            self.arp_missing_addr_mapping(ifid, pkt)?;
            return Ok(())
        };

        let Some(iface) = self.interfaces2.get_mut(&ifid) else {
            return Err(Error::new(
                ErrorKind::Other,
                "interface does not exist anymore"
            ));
        };

        let msg = Message::new()
            .kind(KIND_IPV4)
            .src(iface.device.addr.into())
            .dest(entry.mac.into())
            .content(pkt)
            .build();

        if buffered {
            iface.send_buffered(msg)
        } else {
            iface.send(msg)
        }
    }

    fn arp_missing_addr_mapping(&mut self, ifid: IfId, pkt: Ipv4Packet) -> io::Result<()> {
        let dest = pkt.dest;
        self.arp.wait_for_arp(pkt);

        log::trace!(target: "inet/arp", "missing address resolution for {}, initiating ARP request", dest);

        let iface = self.interfaces2.get_mut(&ifid).unwrap();
        let request = ARPPacket {
            htype: 1,
            ptype: 0x0800,
            operation: ARPOperation::Request,
            src_haddr: iface.device.addr,
            src_paddr: iface.ipv4_addr().unwrap_or(Ipv4Addr::UNSPECIFIED),
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
