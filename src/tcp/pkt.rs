use std::{
    fmt::Display,
    io::{Error, ErrorKind, Read},
};

use bytestream::{ByteOrder::BigEndian, StreamReader, StreamWriter};
use inet_types::{FromBytestream, IntoBytestream};

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
    pub options: Vec<TcpOption>,

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

/// Options of a [`TcpPacket`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TcpOption {
    MaximumSegmentSize(u16),
    WindowScaling(u8),
    Timestamp(u32, u32),
    EndOfOptionsList(),
}

macro_rules! fimpl {
    ($i:ident) => {
        pub fn $i(mut self, value: bool) -> Self {
            self.$i = value;
            self
        }
    };
}

impl TcpPacket {
    pub fn rst_for_syn(syn: &TcpPacket) -> TcpPacket {
        TcpPacket {
            src_port: syn.dest_port,
            dest_port: syn.src_port,
            seq_no: 0,
            ack_no: syn.seq_no,
            flags: TcpFlags::new().ack(true).rst(true),
            window: 0,
            urgent_ptr: 0,
            options: Vec::new(),
            content: Vec::new(),
        }
    }
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

        let mut options_buf = Vec::new();
        for option in self.options.iter() {
            option.into_bytestream(&mut options_buf)?;
        }
        if !options_buf.is_empty() {
            if *self.options.last().unwrap() != TcpOption::EndOfOptionsList() {
                return Err(Error::new(
                    ErrorKind::Other,
                    "missing end of options list tag",
                ));
            }
            // Add padding
            let rem = 4 - (options_buf.len() % 4);
            for _ in 0..rem {
                options_buf.push(0);
            }
        }

        let hlen = 20 + options_buf.len();
        let hlen = hlen / 4;
        let hlen = (0b1111_0000 & (hlen << 4)) as u8;

        hlen.write_to(bytestream, BigEndian)?;
        self.flags.into_bytestream(bytestream)?;
        self.window.write_to(bytestream, BigEndian)?;

        0u16.write_to(bytestream, BigEndian)?;
        self.urgent_ptr.write_to(bytestream, BigEndian)?;

        bytestream.write_all(&options_buf)?;

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

        byte.write_to(bytestream, BigEndian)?;

        Ok(())
    }
}

impl IntoBytestream for TcpOption {
    type Error = std::io::Error;
    fn into_bytestream(&self, bytestream: &mut impl std::io::Write) -> Result<(), Self::Error> {
        match self {
            Self::MaximumSegmentSize(mss) => {
                2u8.write_to(bytestream, BigEndian)?;
                4u8.write_to(bytestream, BigEndian)?;
                mss.write_to(bytestream, BigEndian)?;
            }
            Self::WindowScaling(cnt) => {
                3u8.write_to(bytestream, BigEndian)?;
                3u8.write_to(bytestream, BigEndian)?;
                cnt.write_to(bytestream, BigEndian)?;
            }
            Self::Timestamp(send, recv) => {
                8u8.write_to(bytestream, BigEndian)?;
                10u8.write_to(bytestream, BigEndian)?;
                send.write_to(bytestream, BigEndian)?;
                recv.write_to(bytestream, BigEndian)?;
            }
            Self::EndOfOptionsList() => {
                0u8.write_to(bytestream, BigEndian)?;
            }
            _ => {}
        }
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

        let hlen = u8::read_from(bytestream, BigEndian)? >> 4 & 0b1111;
        let flags = TcpFlags::from_bytestream(bytestream)?;
        let window = u16::read_from(bytestream, BigEndian)?;

        let _ = u16::read_from(bytestream, BigEndian)?;
        let urgent_ptr = u16::read_from(bytestream, BigEndian)?;

        let options_len = hlen * 4 - 20;
        let mut options = Vec::new();

        if options_len > 0 {
            let mut opt_buf = vec![0u8; options_len as usize];
            bytestream.read_exact(&mut opt_buf);

            let mut opt_buf = std::io::Cursor::new(opt_buf);
            loop {
                let option = TcpOption::from_bytestream(&mut opt_buf)?;
                options.push(option);
                if option == TcpOption::EndOfOptionsList() {
                    break;
                }
            }
        }

        let mut content = Vec::new();
        bytestream.read_to_end(&mut content)?;

        Ok(TcpPacket {
            src_port,
            dest_port,
            seq_no,
            ack_no,
            flags,
            window,
            urgent_ptr,
            options,
            content,
        })
    }
}

impl FromBytestream for TcpFlags {
    type Error = std::io::Error;
    fn from_bytestream(
        bytestream: &mut std::io::Cursor<impl AsRef<[u8]>>,
    ) -> Result<Self, Self::Error> {
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

impl FromBytestream for TcpOption {
    type Error = std::io::Error;
    fn from_bytestream(
        bytestream: &mut std::io::Cursor<impl AsRef<[u8]>>,
    ) -> Result<Self, Self::Error> {
        let kind = u8::read_from(bytestream, BigEndian)?;
        if kind == 0 {
            return Ok(Self::EndOfOptionsList());
        }

        let len = u8::read_from(bytestream, BigEndian)? - 2;
        let mut bytes = vec![0u8; len as usize];
        bytestream.read_exact(&mut bytes)?;

        let mut bytes = std::io::Cursor::new(bytes);

        match kind {
            2 => {
                let mss = u16::read_from(&mut bytes, BigEndian)?;
                Ok(Self::MaximumSegmentSize(mss))
            }
            3 => {
                let cnt = u8::read_from(&mut bytes, BigEndian)?;
                Ok(Self::WindowScaling(cnt))
            }
            8 => {
                let send = u32::read_from(&mut bytes, BigEndian)?;
                let recv = u32::read_from(&mut bytes, BigEndian)?;
                Ok(Self::Timestamp(send, recv))
            }
            _ => Err(Error::new(ErrorKind::Other, "invalid tcp options kind")),
        }
    }
}
