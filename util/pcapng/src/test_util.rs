use bytepack::{FromBytestream, ToBytestream};
use des::net::panic;

use super::{
    Block, BlockReader, BlockWriter, DefaultBlockWriter, EnhancedPacketOptionFlags,
    InterfaceDescriptionOption, Linktype, MacAddress,
};
use std::io::{Error, Read, Result, Seek};

/// A writer for tests, that compares the generated output to
/// an expected packet capture.
#[derive(Debug)]
pub struct TestBlockWriter<I: PartialEq + Clone> {
    reader: BlockReader,
    writer: DefaultBlockWriter<Vec<u8>, I>,
}

impl<I: PartialEq + Clone> TestBlockWriter<I> {
    /// Creates a new Writer, that expects a certain block sequence, defined by `expected`.
    ///
    /// # Errors
    ///
    /// Returns and error, if block encoding failed.
    pub fn new<R: Read + Seek + 'static>(expected: R, appl_name: &str) -> Result<Self> {
        Ok(Self {
            reader: BlockReader::new(expected),
            writer: DefaultBlockWriter::new(Vec::new(), appl_name)?,
        })
    }

    fn compare_block_output(&mut self) {
        while !self.writer.output.is_empty() {
            let Ok(block) = Block::read_from_vec(&mut self.writer.output) else {
                panic("block parsing error");
            };
            let Some(expected) = self.reader.next() else {
                panic("no further block was expected, but one was found");
            };
            let Ok(expected) = expected else {
                panic("block parsing error");
            };
            if block != expected {
                panic(format!(
                    "values not equal 'lhs != rhs'\nlhs: {block:#?}\nrhs: {expected:#?}"
                ));
            }
        }
    }
}

impl<I: PartialEq + Clone> BlockWriter<I> for TestBlockWriter<I> {
    fn add_interface(
        &mut self,
        id: &I,
        link_type: Linktype,
        snap_len: u32,
        options: Vec<InterfaceDescriptionOption>,
    ) -> Result<()> {
        self.writer
            .add_interface(id, link_type, snap_len, options)?;
        self.compare_block_output();
        Ok(())
    }

    fn has_interface(&self, id: &I) -> bool {
        self.writer.has_interface(id)
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
        self.writer
            .add_packet(iface, ts, eth_src, eth_dst, eth_kind, pkt, flags)?;
        self.compare_block_output();
        Ok(())
    }

    fn flush(&mut self) -> Result<()> {
        self.writer.flush()
    }
}
