#![warn(clippy::pedantic)]
use bytes_io::ToBytes;
use des::prelude::*;
use inet::{
    interface::{IfId, InterfaceController},
    libpcap::{PcapCapturePoint, PcapEnvelope, PcapSubscriber, set_pcap_deamon},
};
use pcapng::{
    BlockWriter, DefaultBlockWriter, InterfaceDescriptionOption, Linktype, TestBlockWriter,
};
use std::io::{BufReader, BufWriter, Error, ErrorKind, Read, Result, Seek, Write};
use types::{
    arp::{ArpPacket, KIND_ARP},
    ip::{Ipv4Packet, Ipv6Packet, KIND_IPV4, KIND_IPV6},
};

/// Applies a new configuration to PCAP, starting a new
/// capturing epoch.
///
/// # Errors
///
/// Fails if the blocker writer cannot be created.
pub fn pcap<W>(out: W) -> Result<()>
where
    W: Write + 'static,
{
    set_pcap_deamon(LibPcapDeamon {
        writer: DefaultBlockWriter::new(BufWriter::new(out), current().path().as_str())?,
    });
    Ok(())
}

/// Applies a new configuration to PCAP, starting a new
/// capturing epoch.
///
/// # Errors
///
/// Fails if the blocker writer cannot be created.
pub fn pcap_for_test<R>(expected: R, diff: &str) -> Result<()>
where
    R: Read + Seek + 'static,
{
    set_pcap_deamon(LibPcapDeamon {
        writer: TestBlockWriter::new(BufReader::new(expected), current().path().as_str(), diff)?,
    });
    Ok(())
}

struct LibPcapDeamon<W: BlockWriter<IfId>> {
    writer: W,
}

impl<W: BlockWriter<IfId>> LibPcapDeamon<W> {
    fn write_iface(&mut self, ifid: IfId, iface: &InterfaceController) -> Result<()> {
        let link_type = if iface.device.is_loopback() {
            Linktype::LOOP
        } else {
            Linktype::ETHERNET
        };

        self.writer.add_interface(
            &ifid,
            link_type,
            4098,
            vec![
                InterfaceDescriptionOption::InterfaceName(format!(
                    "{} ({})",
                    iface.name,
                    iface.name.id()
                )),
                InterfaceDescriptionOption::InterfaceDescription(format!(
                    "{} ({}) @ {:?}",
                    iface.name,
                    iface.name.id(),
                    iface.device
                )),
            ],
        )
    }

    fn write_packet(&mut self, ifid: IfId, msg: &Message) -> Result<()> {
        self.writer.add_packet(
            &ifid,
            u64::try_from(SimTime::now().as_millis()).expect("can no longer repr timestamü"),
            msg.header.src,
            msg.header.dst,
            msg.header.kind,
            &Self::pkt_as_buf(msg)?,
            None,
        )
    }

    fn pkt_as_buf(msg: &Message) -> Result<Vec<u8>> {
        match msg.header.kind {
            KIND_IPV4 => msg
                .body
                .try_content::<Ipv4Packet>()
                .ok_or(Error::new(
                    ErrorKind::InvalidInput,
                    "Packet of kind {KIND_ARP} did not contain Arp Packet",
                ))?
                .write_to_vec(),
            KIND_IPV6 => msg
                .body
                .try_content::<Ipv6Packet>()
                .ok_or(Error::new(
                    ErrorKind::InvalidInput,
                    "Packet of kind {KIND_ARP} did not contain Arp Packet",
                ))?
                .write_to_vec(),
            KIND_ARP => msg
                .body
                .try_content::<ArpPacket>()
                .ok_or(Error::new(
                    ErrorKind::InvalidInput,
                    "Packet of kind {KIND_ARP} did not contain Arp Packet",
                ))?
                .write_to_vec(),
            _ => Err(Error::new(ErrorKind::Unsupported, "unsupported ethertyp")),
        }
    }
}

impl<W: BlockWriter<IfId>> PcapSubscriber for LibPcapDeamon<W> {
    fn enable_capture(&self, _point: PcapCapturePoint) -> bool {
        true
    }

    fn capture(&mut self, pkt: PcapEnvelope<'_>) -> Result<()> {
        let ifid = pkt.iface.name.id();
        if !self.writer.has_interface(&ifid) {
            self.write_iface(ifid, pkt.iface)?;
        }
        self.write_packet(ifid, pkt.message)
    }
}
