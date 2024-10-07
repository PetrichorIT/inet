use super::{
    EnhancedPacketBlock, EnhancedPacketOption, EnhancedPacketOptionFlags,
    InterfaceDescriptionBlock, InterfaceDescriptionOption, Linktype, MacAddress,
    SectionHeaderBlock, SectionHeaderOption,
};

use bytepack::ToBytestream;
use std::io::{Error, ErrorKind, Result, Write};

/// A generic writer for PCAPNG blocks.
pub trait BlockWriter<I> {
    /// Adds a interface description to the writer.
    ///
    /// # Errors
    ///
    /// Fails if the encoding of the interface description block failed, or the output
    /// is no longer writable.
    fn add_interface(
        &mut self,
        id: &I,
        link_type: Linktype,
        snap_len: u32,
        options: Vec<InterfaceDescriptionOption>,
    ) -> Result<()>;

    /// Indicates, if an interface was already added.
    fn has_interface(&self, id: &I) -> bool;

    /// Adds a packet to the writer.
    ///
    /// # Errors
    ///
    /// Fails if the encoding of the enhanced packet block failed, or the output
    /// is no longer writable.
    #[allow(clippy::too_many_arguments)]
    fn add_packet(
        &mut self,
        iface: &I,
        ts: u64,
        eth_src: MacAddress,
        eth_dst: MacAddress,
        eth_kind: u16,
        pkt: &impl ToBytestream<Error = Error>,
        flags: Option<EnhancedPacketOptionFlags>,
    ) -> Result<()>;

    /// Flushes the inner output device
    ///
    /// # Errors
    ///
    /// See [flush](std::io::Write::flush).
    fn flush(&mut self) -> Result<()>;
}

/// A PCAPNG block writer, that writes to an abitrary output device.
#[derive(Debug)]
pub struct DefaultBlockWriter<W: Write, I: PartialEq + Clone> {
    pub(crate) output: W,
    interfaces: Vec<(I, Linktype)>,
    packet_count: usize,
}

impl<W: Write, I: PartialEq + Clone> DefaultBlockWriter<W, I> {
    /// Creates a new writer, that writes blocks to a output device.
    ///
    /// # Errors
    ///
    /// This call fails, if the writer is not writable or the encoding of
    /// section header block failed.
    pub fn new(mut output: W, appl_name: &str) -> Result<Self> {
        let shb = SectionHeaderBlock {
            version_major: 1,
            version_minor: 0,
            section_len: u64::from(u32::MAX),
            options: vec![
                SectionHeaderOption::HardwareName("des v0.6.1".to_string()),
                SectionHeaderOption::OperatingSystem("inet v0.1.0".to_string()),
                SectionHeaderOption::UserApplication(appl_name.to_string()),
            ],
        };
        output.write_all(&shb.to_vec()?)?;
        Ok(Self {
            output,
            interfaces: Vec::new(),
            packet_count: 0,
        })
    }

    fn write_zero_packet(&mut self) -> Result<()> {
        let ebp = EnhancedPacketBlock {
            interface_id: 0,
            ts: 0,
            org_len: 14,
            data: vec![0x00; 14],
            options: Vec::new(),
        };
        self.output.write_all(&ebp.to_vec()?)
    }
}

impl<W: Write, I: PartialEq + Clone> BlockWriter<I> for DefaultBlockWriter<W, I> {
    fn add_interface(
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

    fn has_interface(&self, id: &I) -> bool {
        self.interfaces.iter().any(|(other, _)| other.eq(id))
    }

    fn add_packet(
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
            interface_id: u32::try_from(interface_id)
                .expect("number of interfaces exceeds u32::MAX"),
            ts,
            org_len: u32::try_from(data.len()).expect("packets can only be u32::MAX bytes long"),
            data,
            options: flags.map_or(Vec::new(), |v| vec![EnhancedPacketOption::Flags(v)]),
        };

        self.packet_count += 1;
        self.output.write_all(&epb.to_vec()?)?;

        Ok(())
    }

    fn flush(&mut self) -> Result<()> {
        self.output.flush()
    }
}

fn ether_typ_to_lo_id(ether: u16) -> u32 {
    match ether {
        0x0800 => 2,
        0x86DD => 30,
        _ => todo!(),
    }
}
