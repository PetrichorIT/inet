use std::io::{BufWriter, Result, Write};

use inet::libpcap::set_pcap_deamon;

use crate::LibPcapDeamon;

use super::config::PcapConfig;

/// Applies a new configuration to PCAP, starting a new
/// capturing epoch.
pub fn pcap<W>(cfg: PcapConfig<W>) -> Result<()>
where
    W: Write + 'static,
{
    let mut pcap = LibPcapDeamon::new();
    pcap.output = BufWriter::new(Box::new(cfg.output));
    pcap.capture = cfg.capture;
    pcap.filters = cfg.filters;
    pcap.ifaces.clear();
    pcap.write_shb()?;

    set_pcap_deamon(pcap);

    Ok(())
}
