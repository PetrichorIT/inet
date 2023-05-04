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
    active: bool,
    ifaces: Vec<IfId>,
    output: Option<BufWriter<File>>,
}

impl Pcap {
    pub(super) fn new() -> Pcap {
        Pcap {
            active: false,
            ifaces: Vec::new(),
            output: None,
        }
    }

    pub(super) fn capture(&mut self, msg: &Message, ifid: IfId, iface: &Interface) -> Result<()> {
        if !self.active {
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
                IDBOption::TimeResoloutionNanos(),
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

        let epb = EPB {
            interface_id: ifidx as u32,
            ts_upper: ts.as_secs() as u32,
            ts_lower: ts.as_nanos() as u32,
            cap_len: buffer.len() as u32,
            org_len: buffer.len() as u32,
            data: buffer,
            // options: Vec::new(),
        };

        epb.write_to(output)
    }
}

// fn main() -> Result<()> {
//     let mut f = File::create("output.pcapng")?;

//     let shb = SHB {
//         block_type: 0x0a0d0d0a,
//         block_len: 28,

//         major: 1,
//         minor: 0,
//         section_len: 0xffffffff_ffffffff,
//         options: Vec::new(),
//     };
//     shb.write_to(&mut f)?;

//     let idb = IDB {
//         link_type: 0x1,
//         snap_len: 4096,
//         options: vec![
//             IDBOption::InterfaceName(
//                 "\\Device\\NPF_{DFA364E5-4A94-4B58-BD9D-617A2C985989}".to_string(),
//             ),
//             IDBOption::InterfaceDescription(
//                 "External 63.237.233.60 (aka 192.168.5.60)".to_string(),
//             ),
//             IDBOption::TimeResoloutionNanos(),
//             IDBOption::OperatingSystem("64-bit Windows Server 2012 R2, build 9600".to_string()),
//         ],
//     };
//     idb.write_to(&mut f)?;

//     let mut buf = vec![
//         0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // src
//         0x00, 0x00, 0x00, 0x00, 0x00, 0x02, // dest
//         // 0x00, 0x00, 0x00, 0x00, // vlan tag
//         0x08, 0x00, // vlan tag
//     ];
//     Ipv4Packet {
//         enc: 0,
//         dscp: 0,
//         identification: 0,
//         flags: Ipv4Flags {
//             mf: false,
//             df: false,
//         },
//         fragment_offset: 0,
//         ttl: 69,
//         proto: 0xff,
//         src: Ipv4Addr::new(1, 1, 2, 2),
//         dest: Ipv4Addr::new(100, 100, 200, 200),
//         content: vec![0xac; 100],
//     }
//     .into_bytestream(&mut buf)
//     .unwrap();
//     buf.extend(&[
//         0x00, 0x00, 0x00, 0x00, // CRC
//     ]);

//     let ebp = EPB {
//         interface_id: 0,
//         ts_upper: 1,
//         ts_lower: 400_000,
//         cap_len: buf.len() as u32,
//         org_len: buf.len() as u32,
//         data: buf,
//         options: Vec::new(),
//     };
//     ebp.write_to(&mut f)?;

//     Ok(())
// }
