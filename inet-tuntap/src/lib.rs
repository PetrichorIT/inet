use std::{
    io::{BufRead, BufReader, Error, ErrorKind, Result},
    process::{Command, Stdio},
    thread,
    time::Duration,
};

use bytes_io::ToBytes;
use des::prelude::Message;
use inet::{
    interface::IfId,
    libpcap::{PcapCapturePoint, PcapEnvelope, PcapSubscriber, set_pcap_deamon},
};

use types::ip::{Ipv4Packet, Ipv6Packet, KIND_IPV4, KIND_IPV6};

/// Applies a new configuration to PCAP, starting a new
/// capturing epoch.
///
/// # Errors
///
/// Fails if the blocker writer cannot be created.
pub fn ptun(name: &str) -> Result<()> {
    // (1) Set capture deemon with TUN device
    set_pcap_deamon(TunDevice {
        writer: tun_rs::DeviceBuilder::new()
            .name(name)
            .mtu(9000)
            .build_sync()?,
    });

    // (2) Spawn wireshark capture, else packets will be lost
    let subprocess = Command::new("wireshark")
        .arg("-i")
        .arg(name)
        .arg("-k")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    eprintln!("** waiting for wireshark on interface {name}");

    // Wait for end of opening dialog
    for line in BufReader::new(subprocess.stderr.unwrap()).lines() {
        let line = line?;
        if line.contains("File:") {
            break;
        }
    }

    // Wait an additional 3s since libcap is sometimes slow
    thread::sleep(Duration::from_secs(3));

    Ok(())
}

struct TunDevice {
    writer: tun_rs::SyncDevice,
}

impl TunDevice {
    fn write_packet(&mut self, _: IfId, msg: &Message) -> Result<()> {
        let as_buf = Self::pkt_as_buf(msg)?;
        self.writer.send(&as_buf)?;
        Ok(())
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
            _ => Err(Error::new(ErrorKind::Unsupported, "unsupported ethertyp")),
        }
    }
}

impl PcapSubscriber for TunDevice {
    fn enable_capture(&self, _point: PcapCapturePoint) -> bool {
        true
    }

    fn capture(&mut self, pkt: PcapEnvelope<'_>) -> Result<()> {
        let ifid = pkt.iface.name.id();
        self.write_packet(ifid, pkt.message)
    }
}

impl Drop for TunDevice {
    fn drop(&mut self) {
        eprintln!(
            "** closing tun device {}",
            self.writer.name().unwrap_or_default()
        );
        thread::sleep(Duration::from_secs(1));
        let _ = self.writer.send(&[]);
    }
}
