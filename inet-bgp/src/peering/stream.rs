use bytepack::FromBytestream;
use inet::TcpStream;
use std::{
    io::Result,
    ops::{Deref, DerefMut},
};
use tokio::io::AsyncReadExt;

use crate::pkt::{BgpPacket, BgpParsingError::*};

pub(super) struct BgpStream {
    buf: Vec<u8>,
    stream: TcpStream,
}

impl BgpStream {
    pub(super) fn new(stream: TcpStream) -> Self {
        Self {
            buf: Vec::with_capacity(1024),
            stream,
        }
    }

    // return done
    pub(super) async fn recv(&mut self) -> Result<bool> {
        let BgpStream { stream, buf } = self;
        match stream.read_buf(buf).await {
            Ok(0) => Ok(true),
            Ok(_) => Ok(false),
            Err(e) => Err(e),
        }
    }

    pub(super) fn next(&mut self) -> Result<Option<BgpPacket>> {
        // At least 19 bytes must be buffered, else incomplete header
        if self.buf.len() < 19 {
            return Ok(None);
        }
        let pkt = BgpPacket::read_from_vec(&mut self.buf);
        match pkt {
            Ok(pkt) => Ok(Some(pkt)),
            // if body is incomplete safe data, (since this is an err, the vec will not have changed)
            Err(Incomplete) => Ok(None),
            Err(Error(e)) => Err(e),
        }
    }
}

impl Deref for BgpStream {
    type Target = TcpStream;
    fn deref(&self) -> &Self::Target {
        &self.stream
    }
}

impl DerefMut for BgpStream {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.stream
    }
}
