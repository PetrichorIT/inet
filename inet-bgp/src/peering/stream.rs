use bytes_io::{BytesMut, FromBytes};
use inet::tcp::TcpStream;
use std::{
    io::{self, Result},
    ops::{Deref, DerefMut},
};
use tokio::io::AsyncReadExt;

use crate::pkt::BgpPacket;

pub(super) struct BgpStream {
    buf: BytesMut,
    stream: TcpStream,
}

impl BgpStream {
    pub(super) fn new(stream: TcpStream) -> Self {
        Self {
            buf: BytesMut::with_capacity(4096),
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
        let pkt = BgpPacket::read_from(&mut self.buf);
        match pkt {
            Ok(pkt) => Ok(Some(pkt)),
            // if body is incomplete safe data, (since this is an err, the vec will not have changed)
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => Ok(None),
            Err(e) => Err(e),
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
