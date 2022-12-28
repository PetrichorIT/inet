use std::{fmt::Display, io::Read};

use crate::{FromBytestream, IntoBytestream};
use bytestream::{ByteOrder::BigEndian, StreamReader, StreamWriter};

/// A TCP packet assosciated with an end-to-end connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpPacket {
    pub src_port: u16,
    pub dest_port: u16,
    pub seq_no: u32,
    pub ack_no: u32,
    pub flags: TcpFlags,
    pub window: u16,
    pub urgent_ptr: u16,

    pub content: Vec<u8>,
}

/// Flags of a [`TcpPacket`].
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TcpFlags {
    pub cwr: bool,
    pub ece: bool,
    pub urg: bool,
    pub ack: bool,
    pub psh: bool,
    pub rst: bool,
    pub syn: bool,
    pub fin: bool,
}

macro_rules! fimpl {
    ($i:ident) => {
        pub fn $i(mut self, value: bool) -> Self {
            self.$i = value;
            self
        }
    };
}

impl TcpFlags {
    pub fn new() -> Self {
        Self::default()
    }
    fimpl!(cwr);
    fimpl!(ece);
    fimpl!(urg);
    fimpl!(ack);
    fimpl!(psh);
    fimpl!(rst);
    fimpl!(syn);
    fimpl!(fin);
}

impl Display for TcpFlags {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.cwr {
            write!(f, "CWR")?
        }
        if self.ece {
            write!(f, "ECE")?
        }
        if self.urg {
            write!(f, "URG")?
        }
        if self.ack {
            write!(f, "ACK")?
        }

        if self.psh {
            write!(f, "PSH")?
        }
        if self.rst {
            write!(f, "RST")?
        }
        if self.syn {
            write!(f, "SYN")?
        }
        if self.fin {
            write!(f, "FIN")?
        }

        Ok(())
    }
}

impl IntoBytestream for TcpPacket {
    type Error = std::io::Error;
    fn into_bytestream(&self, bytestream: &mut impl std::io::Write) -> Result<(), Self::Error> {
        self.src_port.write_to(bytestream, BigEndian)?;
        self.dest_port.write_to(bytestream, BigEndian)?;

        self.seq_no.write_to(bytestream, BigEndian)?;
        self.ack_no.write_to(bytestream, BigEndian)?;

        self.flags.into_bytestream(bytestream)?;
        self.window.write_to(bytestream, BigEndian)?;

        0u16.write_to(bytestream, BigEndian)?;
        self.urgent_ptr.write_to(bytestream, BigEndian)?;

        bytestream.write_all(&self.content)?;

        Ok(())
    }
}

impl IntoBytestream for TcpFlags {
    type Error = std::io::Error;
    fn into_bytestream(&self, bytestream: &mut impl std::io::Write) -> Result<(), Self::Error> {
        let mut byte = 0u8;
        if self.cwr {
            byte |= 0b1000_0000
        }
        if self.ece {
            byte |= 0b0100_0000
        }
        if self.urg {
            byte |= 0b0010_0000
        }
        if self.ack {
            byte |= 0b0001_0000
        }

        if self.psh {
            byte |= 0b0000_1000
        }
        if self.rst {
            byte |= 0b0000_0100
        }
        if self.syn {
            byte |= 0b0000_0010
        }
        if self.fin {
            byte |= 0b0000_0001
        }

        0u8.write_to(bytestream, BigEndian)?;
        byte.write_to(bytestream, BigEndian)?;

        Ok(())
    }
}

impl FromBytestream for TcpPacket {
    type Error = std::io::Error;
    fn from_bytestream(
        bytestream: &mut std::io::Cursor<impl AsRef<[u8]>>,
    ) -> Result<Self, Self::Error> {
        let src_port = u16::read_from(bytestream, BigEndian)?;
        let dest_port = u16::read_from(bytestream, BigEndian)?;

        let seq_no = u32::read_from(bytestream, BigEndian)?;
        let ack_no = u32::read_from(bytestream, BigEndian)?;

        let flags = TcpFlags::from_bytestream(bytestream)?;
        let window = u16::read_from(bytestream, BigEndian)?;

        let _ = u16::read_from(bytestream, BigEndian)?;
        let urgent_ptr = u16::read_from(bytestream, BigEndian)?;

        let mut buf = Vec::new();
        bytestream.read_to_end(&mut buf)?;

        Ok(TcpPacket {
            src_port,
            dest_port,
            seq_no,
            ack_no,
            flags,
            window,
            urgent_ptr,
            content: buf,
        })
    }
}

impl FromBytestream for TcpFlags {
    type Error = std::io::Error;
    fn from_bytestream(
        bytestream: &mut std::io::Cursor<impl AsRef<[u8]>>,
    ) -> Result<Self, Self::Error> {
        let _ = u8::read_from(bytestream, BigEndian)?;
        let byte = u8::read_from(bytestream, BigEndian)?;

        let cwr = byte & 0b1000_0000 != 0;
        let ece = byte & 0b0100_0000 != 0;
        let urg = byte & 0b0010_0000 != 0;
        let ack = byte & 0b0001_0000 != 0;
        let psh = byte & 0b0000_1000 != 0;
        let rst = byte & 0b0000_0100 != 0;
        let syn = byte & 0b0000_0010 != 0;
        let fin = byte & 0b0000_0001 != 0;

        Ok(TcpFlags {
            cwr,
            ece,
            urg,
            ack,
            psh,
            rst,
            syn,
            fin,
        })
    }
}
