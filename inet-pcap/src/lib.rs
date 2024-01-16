use bytepack::ToBytestream;
use des::prelude::*;
use inet::{
    interface::{IfId, Interface},
    libpcap::{PcapCapturePoint, PcapEnvelope, PcapSubscriber},
};
use inet_types::{
    arp::{ArpPacket, KIND_ARP},
    ip::{IpPacketRef, Ipv4Packet, Ipv6Packet, KIND_IPV4, KIND_IPV6},
};
use std::io::{BufWriter, Error, ErrorKind, Result, Write};

mod api;
mod blocks;
mod config;
mod linktype;

use blocks::*;

use linktype::Linktype;

pub use api::pcap;
pub use config::*;

struct LibPcapDeamon {
    output: BufWriter<Box<dyn Write>>,
    capture: PcapCapturePoints,
    filters: PcapFilters,
    ifaces: Vec<IfaceInfo>,
}

struct IfaceInfo {
    ifid: IfId,
    link_type: Linktype,
}

impl LibPcapDeamon {
    fn new() -> LibPcapDeamon {
        LibPcapDeamon {
            output: BufWriter::new(Box::new(Null)),
            capture: PcapCapturePoints::default(),
            filters: PcapFilters::default(),
            ifaces: Vec::new(),
        }
    }

    fn write_shb(&mut self) -> Result<()> {
        let shb = SHB {
            section_len: 0xffff_ffff_ffff_ffff,
            options: vec![
                SHBOption::HardwareName(format!(
                    "(des/inet) simulated node :: {}",
                    current().path()
                )),
                SHBOption::OperatingSystem(format!("des/inet")),
                SHBOption::UserApplication(format!("des/inet")),
            ],
        };
        self.output.write_all(&shb.to_vec()?)
    }

    fn write_iface(&mut self, ifid: IfId, iface: &Interface) -> Result<()> {
        let link_type = if iface.device.is_loopback() {
            Linktype::LOOP
        } else {
            Linktype::ETHERNET
        };

        let idb = IDB {
            link_type,
            snap_len: 4098, // TODO limit interface mss,
            options: vec![
                IDBOption::InterfaceName(format!("{} ({})", iface.name, iface.name.id())),
                IDBOption::InterfaceDescription(format!(
                    "{} ({}) @ {:?}",
                    iface.name,
                    iface.name.id(),
                    iface.device
                )),
                // IDBOption::TimeResoloutionNanos(),
            ],
        };

        let buf = idb.to_vec()?;
        self.output.write_all(&buf)?;
        self.ifaces.push(IfaceInfo { ifid, link_type });

        // FIXME: dirty hack only temporary
        if self.ifaces.len() == 1 {
            // Write a empty ethernet packet to get absolute timestamps
            let buffer = vec![0x00; 14];
            let ebp = EPB {
                interface_id: 0,
                ts: SimTime::ZERO.as_micros() as u64,
                cap_len: buffer.len() as u32,
                org_len: buffer.len() as u32,
                data: buffer,
            };
            self.output.write_all(&ebp.to_vec()?)?;
        }

        Ok(())
    }

    fn write_packet(&mut self, ifidx: usize, link_type: Linktype, msg: &Message) -> Result<()> {
        let mut buffer = Vec::new();

        // (0) Check filters first
        let mut state = FilterResult::Continue;
        for filter in self.filters.iter() {
            state = filter.evaluate_l2(state, msg);
        }

        match link_type {
            Linktype::ETHERNET => {
                // Write the contents, that are not yet byte encoded, so encode them
                buffer.write_all(&msg.header().dest)?;
                buffer.write_all(&msg.header().src)?;
                buffer.write_all(&msg.header().kind.to_be_bytes())?;
                buffer = match self.write_l3_packet(msg, state, buffer) {
                    Ok(buffer) => buffer,
                    Err(e) if e.kind() == ErrorKind::PermissionDenied => return Ok(()),
                    Err(e) => return Err(e),
                };

                // Ethernet header part 2
                buffer.write_all(&[0x00, 0x00, 0x00, 0x00])?;
            }

            Linktype::LOOP => {
                // Write the contents, that are not yet byte encoded, so encode them
                buffer.write_all(&ether_typ_to_lo_id(msg.header().kind).to_be_bytes())?;
                buffer = match self.write_l3_packet(msg, state, buffer) {
                    Ok(buffer) => buffer,
                    Err(e) if e.kind() == ErrorKind::PermissionDenied => return Ok(()),
                    Err(e) => return Err(e),
                };
            }
            _ => todo!(),
        }

        let ts = SimTime::now();
        let micros = ts.as_micros() as u64;
        let epb = EPB {
            interface_id: ifidx as u32,
            ts: micros,
            cap_len: buffer.len() as u32,
            org_len: buffer.len() as u32,
            data: buffer,
            // options: Vec::new(),
        };

        self.output.write_all(&epb.to_vec()?)
    }

    fn write_l3_packet(
        &mut self,
        msg: &Message,
        mut state: FilterResult,
        mut buffer: Vec<u8>,
    ) -> Result<Vec<u8>> {
        match msg.header().kind {
            KIND_ARP => {
                let pkt = msg.try_content::<ArpPacket>().ok_or(Error::new(
                    ErrorKind::InvalidInput,
                    "Packet of kind {KIND_ARP} did not contain Arp Packet",
                ))?;

                for filter in self.filters.iter() {
                    state = filter.evaluate_fin(state);
                }

                if state != FilterResult::Allow {
                    return Err(Error::new(ErrorKind::PermissionDenied, "filter denied"));
                }
                // Ethernet header part 1
                pkt.append_to_vec(&mut buffer)?;
            }
            KIND_IPV4 => {
                let pkt = msg.try_content::<Ipv4Packet>().ok_or(Error::new(
                    ErrorKind::InvalidInput,
                    "Packet of kind {KIND_IPV4} did not contain Ipv4 Packet",
                ))?;

                for filter in self.filters.iter() {
                    state = filter.evaluate_l3(state, &IpPacketRef::V4(pkt));
                    state = filter.evaluate_fin(state);
                }
                if state != FilterResult::Allow {
                    return Err(Error::new(ErrorKind::PermissionDenied, "filter denied"));
                }
                // Ethernet header part 1
                pkt.append_to_vec(&mut buffer)?;
            }
            KIND_IPV6 => {
                let pkt = msg.try_content::<Ipv6Packet>().ok_or(Error::new(
                    ErrorKind::InvalidInput,
                    "Packet of kind {KIND_IPV6} did not contain Ipv6 Packet",
                ))?;

                for filter in self.filters.iter() {
                    state = filter.evaluate_l3(state, &IpPacketRef::V6(pkt));
                    state = filter.evaluate_fin(state);
                }
                if state != FilterResult::Allow {
                    return Err(Error::new(ErrorKind::PermissionDenied, "filter denied"));
                }

                // Ethernet header part 1
                pkt.append_to_vec(&mut buffer)?;
            }
            _ => {
                tracing::error!("unknown packet");
            }
        }

        Ok(buffer)
    }
}

fn ether_typ_to_lo_id(ether: MessageKind) -> u32 {
    match ether {
        KIND_IPV4 => 2,
        KIND_IPV6 => 30,
        _ => todo!(),
    }
}

impl PcapSubscriber for LibPcapDeamon {
    fn enable_capture(&self, point: PcapCapturePoint) -> bool {
        match point {
            PcapCapturePoint::Ingress => matches!(
                self.capture,
                PcapCapturePoints::Ingress | PcapCapturePoints::All
            ),
            PcapCapturePoint::Egress => matches!(
                self.capture,
                PcapCapturePoints::Egress | PcapCapturePoints::All
            ),
        }
    }

    fn capture(&mut self, pkt: PcapEnvelope<'_>) -> Result<()> {
        let (ifidx, info) = if let Some(ifidx) = self
            .ifaces
            .iter()
            .enumerate()
            .find(|(_, s_ifid)| s_ifid.ifid == pkt.iface.name.id())
        {
            ifidx
        } else {
            self.write_iface(pkt.iface.name.id(), pkt.iface)?;
            return self.capture(pkt);
        };

        self.write_packet(ifidx, info.link_type, pkt.message)
    }

    fn close(&mut self) -> Result<()> {
        self.output.flush()
    }
}
