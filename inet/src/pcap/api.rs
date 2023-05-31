use std::io::{BufWriter, Result, Write};

use super::config::PcapConfig;
use crate::IOContext;

/// Applies a new configuration to PCAP, starting a new
/// capturing epoch.
pub fn pcap<W>(cfg: PcapConfig<W>) -> Result<()>
where
    W: Write + 'static,
{
    IOContext::failable_api(|ctx| {
        let mut pcap = ctx.pcap.borrow_mut();
        pcap.output = BufWriter::new(Box::new(cfg.output));
        pcap.capture = cfg.capture;
        pcap.filters = cfg.filters;
        pcap.ifaces.clear();
        pcap.write_shb()?;

        Ok(())
    })
}
