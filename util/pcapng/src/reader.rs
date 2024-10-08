use crate::Block;
use bytepack::FromBytestream;
use std::{
    fmt::Debug,
    io::{BufReader, ErrorKind, Read, Result, Seek},
};

/// A lazy reader, that reads PCAPNG blocks from a input device.
pub struct BlockReader {
    buffer: Vec<u8>,
    expected: Box<dyn ReadAndSeek>,
}

impl BlockReader {
    /// Creates a new PCAPNG block reader, that lazy-reads data from a
    /// `Read + Seek` object.
    pub fn new<R>(input: R) -> Self
    where
        R: Read + Seek + 'static,
    {
        Self {
            buffer: Vec::with_capacity(4096),
            expected: Box::new(BufReader::new(input)),
        }
    }
}

macro_rules! try_err {
    ($($t:tt)*) => {
        match ($($t)*) {
            Ok(v) => v,
            Err(e) => return Some(Err(e))
        }
    };
}

impl Iterator for BlockReader {
    type Item = Result<Block>;
    fn next(&mut self) -> Option<Self::Item> {
        self.buffer.clear();
        self.buffer.extend_from_slice(&[0; 8]);
        match self.expected.read_exact(&mut self.buffer) {
            Ok(()) => {}
            Err(e) if e.kind() == ErrorKind::UnexpectedEof => return None,
            Err(e) => return Some(Err(e)),
        };

        let block_len = u32::from_slice(&self.buffer[4..])
            .expect("4 bytes as confirmed by if clause")
            .to_be();
        self.buffer.resize(block_len as usize, 0);
        try_err!(self.expected.read_exact(&mut self.buffer[8..]));

        Some(Block::read_from_vec(&mut self.buffer))
    }
}

impl DoubleEndedIterator for BlockReader {
    fn next_back(&mut self) -> Option<Self::Item> {
        let mut buf = vec![0; 4];
        if try_err!(self.expected.stream_position()) == 0 {
            return None;
        }

        try_err!(self.expected.seek_relative(-4));
        let n = try_err!(self.expected.read(&mut buf));
        match n {
            4 => {
                let block_len = u32::from_slice(&buf[..])
                    .expect("4 bytes as confirmed by if clause")
                    .to_be();
                try_err!(self.expected.seek_relative(-i64::from(block_len)));

                let mut buf = vec![0; block_len as usize];
                try_err!(self.expected.read_exact(&mut buf));

                try_err!(self.expected.seek_relative(-i64::from(block_len)));

                Some(Block::read_from_vec(&mut buf))
            }
            0 => None,
            _ => todo!(),
        }
    }
}

impl Debug for BlockReader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BlockReader").finish()
    }
}

trait ReadAndSeek: Read + Seek {}

impl<T: Read + Seek> ReadAndSeek for T {}
