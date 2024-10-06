use bytepack::ToBytestream;
use std::io::{Error, ErrorKind, Result, Write};

mod blocks;
mod linktype;

#[cfg(test)]
mod tests;

pub use blocks::*;
pub use linktype::Linktype;

type MacAddress = [u8; 6];

pub struct Session<I: PartialEq + Clone> {
    output: Box<dyn Write>,
    interfaces: Vec<(I, Linktype)>,
    packet_count: usize,
}

impl<I: PartialEq + Clone> Session<I> {
    pub fn new(mut output: impl Write + 'static, appl_name: &str) -> Result<Self> {
        let shb = SectionHeaderBlock {
            version_major: 1,
            version_minor: 0,
            section_len: u32::MAX as u64,
            options: vec![
                SectionHeaderOption::HardwareName("des v0.6.1".to_string()),
                SectionHeaderOption::OperatingSystem("inet v0.1.0".to_string()),
                SectionHeaderOption::UserApplication(appl_name.to_string()),
            ],
        };
        output.write_all(&shb.to_vec()?)?;
        Ok(Self {
            output: Box::new(output),
            interfaces: Vec::new(),
            packet_count: 0,
        })
    }

    pub fn add_interface(
        &mut self,
        id: &I,
        link_type: Linktype,
        snap_len: u32,
        options: Vec<InterfaceDescriptionOption>,
    ) -> Result<()> {
        let idb = InterfaceDescriptionBlock {
            link_type,
            snap_len,
            options,
        };
        self.output.write_all(&idb.to_vec()?)?;
        self.interfaces.push((id.clone(), link_type));

        if self.interfaces.len() == 1 {
            self.write_zero_packet()?;
        }
        Ok(())
    }

    pub fn has_interface(&self, id: &I) -> bool {
        self.interfaces.iter().any(|(other, _)| other.eq(id))
    }

    pub fn add_packet(
        &mut self,
        iface: &I,
        ts: u64,
        eth_src: MacAddress,
        eth_dst: MacAddress,
        eth_kind: u16,
        pkt: &impl ToBytestream<Error = Error>,
        flags: Option<EnhancedPacketOptionFlags>,
    ) -> Result<()> {
        let (interface_id, (_, link_type)) = self
            .interfaces
            .iter()
            .enumerate()
            .find(|(_, (other, _))| other.eq(iface))
            .ok_or(Error::new(
                ErrorKind::InvalidInput,
                "no such interface registered",
            ))?;

        let data = match *link_type {
            Linktype::ETHERNET => {
                let mut data = Vec::new();

                // Ethernet header part 1
                data.write_all(&eth_dst)?;
                data.write_all(&eth_src)?;
                data.write_all(&eth_kind.to_be_bytes())?;

                // Packet
                pkt.append_to_vec(&mut data)?;

                // Ethernet header part 2
                data.write_all(&[0x00, 0x00, 0x00, 0x00])?;
                data
            }
            Linktype::LOOP => {
                let mut data = Vec::new();

                // Ethernet header part 1
                data.write_all(&ether_typ_to_lo_id(eth_kind).to_be_bytes())?;

                // Packet
                pkt.append_to_vec(&mut data)?;

                // Ethernet header part 2
                data.write_all(&[0x00, 0x00, 0x00, 0x00])?;
                data
            }
            _ => todo!(),
        };

        let epb = EnhancedPacketBlock {
            interface_id: interface_id as u32,
            ts,
            org_len: data.len() as u32,
            data,
            options: flags.map_or(Vec::new(), |v| vec![EnhancedPacketOption::Flags(v)]),
        };

        self.packet_count += 1;
        self.output.write_all(&epb.to_vec()?)?;

        Ok(())
    }

    pub fn flush(&mut self) -> Result<()> {
        self.output.flush()
    }

    fn write_zero_packet(&mut self) -> Result<()> {
        let ebp = EnhancedPacketBlock {
            interface_id: 0,
            ts: 0,
            org_len: 14 as u32,
            data: vec![0x00; 14],
            options: Vec::new(),
        };
        self.output.write_all(&ebp.to_vec()?)
    }
}

fn ether_typ_to_lo_id(ether: u16) -> u32 {
    match ether {
        0x0800 => 2,
        0x86DD => 30,
        _ => todo!(),
    }
}
