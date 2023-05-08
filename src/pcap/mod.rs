//! Capturing packets and storing them as .pcapng files.

use self::blocks::{IDBOption, SHBOption, EPB, IDB, SHB};
use crate::interface::{IfId, Interface};
use des::{
    prelude::{module_path, Message},
    time::SimTime,
};
use inet_types::arp::{ArpPacket, KIND_ARP};
use inet_types::{
    ip::{Ipv4Packet, Ipv6Packet, KIND_IPV4, KIND_IPV6},
    IntoBytestream,
};
use std::{
    fs::File,
    io::{BufWriter, Error, ErrorKind, Result, Write},
};

mod api;
mod blocks;

pub use self::api::*;

pub(crate) struct Pcap {
    pub cfg: PcapConfig,
    ifaces: Vec<IfId>,
    output: Option<BufWriter<File>>,
}

impl Pcap {
    pub(super) fn new() -> Pcap {
        Pcap {
            cfg: PcapConfig::default(),
            ifaces: Vec::new(),
            output: None,
        }
    }

    pub(super) fn capture(&mut self, msg: &Message, ifid: IfId, iface: &Interface) -> Result<()> {
        if !self.cfg.enable {
            return Ok(());
        }

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
        self.output
            .as_mut()
            .map(|o| shb.write_to(o))
            .unwrap_or(Err(Error::new(
                ErrorKind::BrokenPipe,
                "no output avialable",
            )))
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

        self.output
            .as_mut()
            .map(|o| idb.write_to(o))
            .unwrap_or(Err(Error::new(
                ErrorKind::BrokenPipe,
                "no output avialable",
            )))?;
        self.ifaces.push(ifid);

        Ok(())
    }

    fn write_packet(&mut self, ifidx: usize, msg: &Message) -> Result<()> {
        let Some(output) = self.output.as_mut() else {
            return Err(Error::new(ErrorKind::BrokenPipe, "no output available"));
        };

        let mut buffer = Vec::new();

        // Ethernet header part 1
        buffer.write_all(&msg.header().dest)?;
        buffer.write_all(&msg.header().src)?;
        buffer.write_all(&msg.header().kind.to_be_bytes())?;

        // Write the contents, that are not yet byte encoded, so encode them
        match msg.header().kind {
            KIND_ARP => {
                let pkt = msg.try_content::<ArpPacket>().ok_or(Error::new(
                    ErrorKind::InvalidInput,
                    "Packet of kind {KIND_ARP} did not contain Arp Packet",
                ))?;
                pkt.to_bytestream(&mut buffer)?;
            }
            KIND_IPV4 => {
                let pkt = msg.try_content::<Ipv4Packet>().ok_or(Error::new(
                    ErrorKind::InvalidInput,
                    "Packet of kind {KIND_IPV4} did not contain Ipv4 Packet",
                ))?;
                pkt.to_bytestream(&mut buffer)?;
            }
            KIND_IPV6 => {
                let pkt = msg.try_content::<Ipv6Packet>().ok_or(Error::new(
                    ErrorKind::InvalidInput,
                    "Packet of kind {KIND_IPV6} did not contain Ipv6 Packet",
                ))?;
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

        epb.write_to(output)
    }
}
