use bytepack::ToBytestream;
use std::io::{Error, ErrorKind, Result, Write};

mod blocks;
mod linktype;

pub use blocks::*;
pub use linktype::Linktype;

pub struct PcapFile {
    inner: Box<dyn Write>,
    interfaces: Vec<String>,
    node_name: String,
    state: State,
    packet_count: usize,
}

enum State {
    Uninitialized,
    Initialized,
}

impl PcapFile {
    pub fn new<W: Write + 'static>(into: W, node_name: impl AsRef<str>) -> Self {
        Self {
            inner: Box::new(into),
            interfaces: Vec::new(),
            state: State::Uninitialized,
            node_name: node_name.as_ref().to_string(),
            packet_count: 0,
        }
    }

    pub fn record_interface(
        &mut self,
        id: &str,
        name: &str,
        description: &str,
        link_type: Linktype,
    ) -> Result<()> {
        self.init_if_nessecary()?;

        let idb = InterfaceDescriptionBlock {
            link_type,
            snap_len: 4098, // TODO limit interface mss,
            options: vec![
                InterfaceDescriptionOption::InterfaceName(name.to_string()),
                InterfaceDescriptionOption::InterfaceDescription(description.to_string()),
                // IDBOption::TimeResoloutionNanos(),
            ],
        };

        let buf = idb.to_vec()?;
        self.inner.write_all(&buf)?;
        self.interfaces.push(id.to_string());

        // FIXME: dirty hack only temporary
        if self.interfaces.len() == 1 {
            // Write a empty ethernet packet to get absolute timestamps
            let buffer = vec![0x00; 14];
            let ebp = EnhancedPacketBlock {
                interface_id: 0,
                ts: 0,
                cap_len: buffer.len() as u32,
                org_len: buffer.len() as u32,
                data: buffer,
            };
            self.inner.write_all(&ebp.to_vec()?)?;
        }

        Ok(())
    }

    pub fn record_eth_packet(
        &mut self,
        iface: &str,
        ts: u64,
        eth_src: &[u8; 6],
        eth_dst: &[u8; 6],
        eth_kind: u16,
        pkt: &impl ToBytestream<Error = Error>,
    ) -> Result<()> {
        // No init_if_nessecary required, since else no iface exists
        // get idx of iface
        let ifidx = self
            .interfaces
            .iter()
            .position(|s| s == iface)
            .ok_or(Error::new(ErrorKind::InvalidInput, "no such interface"))?;

        let mut buffer = Vec::new();

        // Ethernet header part 1
        buffer.write_all(eth_dst)?;
        buffer.write_all(eth_src)?;
        buffer.write_all(&eth_kind.to_be_bytes())?;

        // Packet
        pkt.append_to_vec(&mut buffer)?;

        // Ethernet header part 2
        buffer.write_all(&[0x00, 0x00, 0x00, 0x00])?;

        // write EPB
        let epb = EnhancedPacketBlock {
            interface_id: ifidx as u32,
            ts,
            cap_len: buffer.len() as u32,
            org_len: buffer.len() as u32,
            data: buffer,
        };

        self.packet_count += 1;
        self.inner.write_all(&epb.to_vec()?)
    }

    pub fn record_loopback_packet(
        &mut self,
        iface: &str,
        ts: u64,
        eth_kind: u16,
        pkt: &impl ToBytestream<Error = Error>,
    ) -> Result<()> {
        // No init_if_nessecary required, since else no iface exists
        // get idx of iface
        let ifidx = self
            .interfaces
            .iter()
            .position(|s| s == iface)
            .ok_or(Error::new(ErrorKind::InvalidInput, "no such interface"))?;

        let mut buffer = Vec::new();

        // Ethernet header part 1
        buffer.write_all(&ether_typ_to_lo_id(eth_kind).to_be_bytes())?;

        // Packet
        pkt.append_to_vec(&mut buffer)?;

        // Ethernet header part 2
        buffer.write_all(&[0x00, 0x00, 0x00, 0x00])?;

        // write EPB
        let epb = EnhancedPacketBlock {
            interface_id: ifidx as u32,
            ts,
            cap_len: buffer.len() as u32,
            org_len: buffer.len() as u32,
            data: buffer,
        };

        self.packet_count += 1;
        self.inner.write_all(&epb.to_vec()?)
    }

    fn init_if_nessecary(&mut self) -> Result<()> {
        if let State::Uninitialized = self.state {
            self.state = State::Initialized;
            let shb = SectionHeaderBlock {
                version_major: 1,
                version_minor: 0,
                section_len: 0xffff_ffff_ffff_ffff,
                options: vec![
                    SectionHeaderOption::HardwareName(format!(
                        "(des/inet) simulated node :: {}",
                        self.node_name
                    )),
                    SectionHeaderOption::OperatingSystem(format!("des/inet")),
                    SectionHeaderOption::UserApplication(format!("des/inet")),
                ],
            };
            self.inner.write_all(&shb.to_vec()?)
        } else {
            Ok(())
        }
    }
}

fn ether_typ_to_lo_id(ether: u16) -> u32 {
    match ether {
        0x0800 => 2,
        0x86DD => 30,
        _ => todo!(),
    }
}
