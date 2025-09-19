use bytes_io::{BufMut, BytesMut, FromBytes};

use crate::Block;
use std::{
    fmt::Debug,
    io::{BufReader, ErrorKind, Read, Result, Seek},
};

/// A lazy reader, that reads PCAPNG blocks from a input device.
pub struct BlockReader {
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
            expected: Box::new(BufReader::new(input)),
        }
    }
}

macro_rules! try_err {
    ($($t:tt)*) => {
        match ($($t)*) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("Error: {}", e);
                return Some(Err(e))}
        }
    };
}

impl Iterator for BlockReader {
    type Item = Result<Block>;
    fn next(&mut self) -> Option<Self::Item> {
        let mut bytes = [0; 8];
        match self.expected.read_exact(&mut bytes[..]) {
            Ok(()) => {}
            Err(e) if e.kind() == ErrorKind::UnexpectedEof => return None,
            Err(e) => return Some(Err(e)),
        }

        let block_len =
            u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]).to_be() as usize;

        let mut buf = BytesMut::with_capacity(block_len + 8);
        buf.put_slice(&bytes);
        buf.put_bytes(0, block_len - 8);

        try_err!(self.expected.read_exact(&mut buf[8..]));

        let mut buf = buf.freeze();
        let result = Block::read_from(&mut buf);

        Some(result)
    }
}

impl DoubleEndedIterator for BlockReader {
    fn next_back(&mut self) -> Option<Self::Item> {
        let mut buf = [0; 4];
        if try_err!(self.expected.stream_position()) == 0 {
            return None;
        }

        try_err!(self.expected.seek_relative(-4));
        let n = try_err!(self.expected.read(&mut buf));
        match n {
            4 => {
                let block_len = u32::from_be_bytes(buf).to_be();
                try_err!(self.expected.seek_relative(-i64::from(block_len)));

                let mut buf = BytesMut::with_capacity(block_len as usize);
                buf.put_bytes(0, block_len as usize);

                try_err!(self.expected.read_exact(&mut buf));

                try_err!(self.expected.seek_relative(-i64::from(block_len)));

                let mut buf = buf.freeze();
                Some(Block::read_from(&mut buf))
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
