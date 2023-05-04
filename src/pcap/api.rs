use std::fs::File;
use std::io::{BufWriter, Error, ErrorKind, Result};

use crate::IOContext;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash)]
pub struct PcapConfig {
    pub enable: bool,
    pub capture: PcapCapture,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash)]
pub enum PcapCapture {
    Incoming,
    Outgoing,
    #[default]
    Both,
}

impl PcapCapture {
    pub(crate) fn capture_incoming(&self) -> bool {
        matches!(self, Self::Incoming | Self::Both)
    }

    pub(crate) fn capture_outgoing(&self) -> bool {
        matches!(self, Self::Outgoing | Self::Both)
    }
}

// Opens a pcap debugger
pub fn pcap(cfg: PcapConfig, output: File) -> Result<()> {
    IOContext::with_current(|ctx| {
        if ctx.pcap.borrow().cfg.enable {
            return Err(Error::new(ErrorKind::Other, "pcap allready enabled"));
        }

        if cfg.enable {
            let mut pcap = ctx.pcap.borrow_mut();
            pcap.output = Some(BufWriter::new(output));
            pcap.ifaces.clear();
            pcap.cfg = cfg;
            pcap.write_shb()?
        }

        Ok(())
    })
}
