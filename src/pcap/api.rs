use std::fs::File;
use std::io::{BufWriter, Error, ErrorKind, Result};

use crate::IOContext;

// Opens a pcap debugger
pub fn pcap(enable: bool, output: File) -> Result<()> {
    IOContext::with_current(|ctx| {
        if ctx.pcap.borrow().active {
            return Err(Error::new(ErrorKind::Other, "pcap allready enabled"));
        }

        if enable {
            let mut pcap = ctx.pcap.borrow_mut();
            pcap.output = Some(BufWriter::new(output));
            pcap.ifaces.clear();
            pcap.active = enable;
            pcap.write_shb()?
        }

        Ok(())
    })
}
