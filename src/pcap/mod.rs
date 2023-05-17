//! Capturing packets and storing them as .pcapng files.

use self::blocks::{IDBOption, SHBOption, EPB, IDB, SHB};
use crate::interface::{IfId, Interface};
use des::{
    prelude::{module_path, Message},
    time::SimTime,
};
use inet_types::{
    arp::{ArpPacket, KIND_ARP},
    ip::IpPacketRef,
};
use inet_types::{
    ip::{Ipv4Packet, Ipv6Packet, KIND_IPV4, KIND_IPV6},
    IntoBytestream,
};
use std::io::{BufWriter, Error, ErrorKind, Result, Write};

mod api;
mod blocks;

pub use self::api::*;

pub(crate) struct Pcap {
    output: BufWriter<Box<dyn Write>>,
    pub(crate) capture: PcapCapturePoints,
    filters: PcapFilters,

    ifaces: Vec<IfId>,
}

struct Null;
impl Write for Null {
    fn write(&mut self, _buf: &[u8]) -> Result<usize> {
        Err(Error::new(
            ErrorKind::BrokenPipe,
            "did not set a output for pcap",
        ))
    }
    fn flush(&mut self) -> Result<()> {
        Err(Error::new(
            ErrorKind::BrokenPipe,
            "did not set a output for pcap",
        ))
    }
}

impl Pcap {
    pub(super) fn new() -> Pcap {
        Pcap {
            output: BufWriter::new(Box::new(Null)),
            capture: PcapCapturePoints::default(),
            filters: PcapFilters::default(),
            ifaces: Vec::new(),
        }
    }

    pub(super) fn capture(&mut self, msg: &Message, ifid: IfId, iface: &Interface) -> Result<()> {
        let ifidx = if let Some(ifidx) = self
            .ifaces
            .iter()
            .enumerate()
            .find(|(_, s_ifid)| **s_ifid == ifid)
            .map(|v| v.0)
        {
            ifidx
        } else {
            let idx = self.ifaces.len();
            self.write_iface(ifid, iface)?;
            idx
        };

        self.write_packet(ifidx, msg)
    }

    fn write_shb(&mut self) -> Result<()> {
        let shb = SHB {
            section_len: 0xffff_ffff_ffff_ffff,
            options: vec![
                SHBOption::HardwareName(format!("(des/inet) simulated node :: {}", module_path())),
                SHBOption::OperatingSystem(format!("des/inet")),
                SHBOption::UserApplication(format!("des/inet")),
            ],
        };
        shb.write_to(&mut self.output)
    }

    fn write_iface(&mut self, ifid: IfId, iface: &Interface) -> Result<()> {
        let idb = IDB {
            link_type: 1,
            snap_len: 4098, // TODO limit interface mss,
            options: vec![
                IDBOption::InterfaceName(format!("{} ({})", iface.name, iface.name.id)),
                IDBOption::InterfaceDescription(format!(
                    "{} ({}) @ {:?}",
                    iface.name, iface.name.id, iface.device
                )),
                // IDBOption::TimeResoloutionNanos(),
            ],
        };

        idb.write_to(&mut self.output)?;
        self.ifaces.push(ifid);

        Ok(())
    }

    fn write_packet(&mut self, ifidx: usize, msg: &Message) -> Result<()> {
        let mut buffer = Vec::new();

        // (0) Check filters first
        let mut state = FilterResult::Continue;
        for filter in &self.filters {
            state = filter.evaluate_l2(state, msg);
        }

        // Write the contents, that are not yet byte encoded, so encode them
        match msg.header().kind {
            KIND_ARP => {
                let pkt = msg.try_content::<ArpPacket>().ok_or(Error::new(
                    ErrorKind::InvalidInput,
                    "Packet of kind {KIND_ARP} did not contain Arp Packet",
                ))?;

                for filter in &self.filters {
                    state = filter.evaluate_fin(state);
                }
                if state == FilterResult::Allow {
                    // Ethernet header part 1
                    buffer.write_all(&msg.header().dest)?;
                    buffer.write_all(&msg.header().src)?;
                    buffer.write_all(&msg.header().kind.to_be_bytes())?;
                    pkt.to_bytestream(&mut buffer)?;
                }
            }
            KIND_IPV4 => {
                let pkt = msg.try_content::<Ipv4Packet>().ok_or(Error::new(
                    ErrorKind::InvalidInput,
                    "Packet of kind {KIND_IPV4} did not contain Ipv4 Packet",
                ))?;

                for filter in &self.filters {
                    state = filter.evaluate_l3(state, &IpPacketRef::V4(pkt));
                    state = filter.evaluate_fin(state);
                }
                if state == FilterResult::Allow {
                    // Ethernet header part 1
                    buffer.write_all(&msg.header().dest)?;
                    buffer.write_all(&msg.header().src)?;
                    buffer.write_all(&msg.header().kind.to_be_bytes())?;
                    pkt.to_bytestream(&mut buffer)?;
                }
            }
            KIND_IPV6 => {
                let pkt = msg.try_content::<Ipv6Packet>().ok_or(Error::new(
                    ErrorKind::InvalidInput,
                    "Packet of kind {KIND_IPV6} did not contain Ipv6 Packet",
                ))?;

                for filter in &self.filters {
                    state = filter.evaluate_l3(state, &IpPacketRef::V6(pkt));
                    state = filter.evaluate_fin(state);
                }
                if state == FilterResult::Allow {
                    // Ethernet header part 1
                    buffer.write_all(&msg.header().dest)?;
                    buffer.write_all(&msg.header().src)?;
                    buffer.write_all(&msg.header().kind.to_be_bytes())?;
                }
                pkt.to_bytestream(&mut buffer)?;
            }
            _ => {
                log::error!("unknown packet");
            }
        }

        // Ethernet header part 2
        buffer.write_all(&[0x00, 0x00, 0x00, 0x00])?;
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

        epb.write_to(&mut self.output)
    }
}
