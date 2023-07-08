use std::{
    fmt::Display,
    io::{Error, ErrorKind, Read, Write},
};

use bytepack::{
    BytestreamReader, BytestreamWriter, FromBytestream, ReadBytesExt, ToBytestream, WriteBytesExt,
    BE,
};

pub const PROTO_TCP: u8 = 0x06;

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
#[allow(clippy::struct_excessive_bools)]
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
        #[must_use]
        pub fn $i(mut self, value: bool) -> Self {
            self.$i = value;
            self
        }
    };
}

impl TcpPacket {
    #[must_use]
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
    #[must_use]
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
            write!(f, "CWR")?;
        }
        if self.ece {
            write!(f, "ECE")?;
        }
        if self.urg {
            write!(f, "URG")?;
        }
        if self.ack {
            write!(f, "ACK")?;
        }

        if self.psh {
            write!(f, "PSH")?;
        }
        if self.rst {
            write!(f, "RST")?;
        }
        if self.syn {
            write!(f, "SYN")?;
        }
        if self.fin {
            write!(f, "FIN")?;
        }

        Ok(())
    }
}

impl ToBytestream for TcpPacket {
    type Error = std::io::Error;
    fn to_bytestream(&self, stream: &mut BytestreamWriter) -> Result<(), Self::Error> {
        stream.write_u16::<BE>(self.src_port)?;
        stream.write_u16::<BE>(self.dest_port)?;

        stream.write_u32::<BE>(self.seq_no)?;
        stream.write_u32::<BE>(self.ack_no)?;

        let hlen_marker = stream.create_typed_marker::<u8>()?;
        self.flags.to_bytestream(stream)?;
        stream.write_u16::<BE>(self.window)?;
        stream.write_u16::<BE>(0)?;
        stream.write_u16::<BE>(self.urgent_ptr)?;

        for option in &self.options {
            option.to_bytestream(stream)?;
        }

        let mut options_len = stream.len_since_marker(&hlen_marker) - 7;
        if options_len > 0 {
            if *self.options.last().unwrap() != TcpOption::EndOfOptionsList() {
                return Err(Error::new(
                    ErrorKind::Other,
                    "missing end of options list tag",
                ));
            }
            // Add padding
            let rem = 4 - (options_len % 4);
            for _ in 0..rem {
                stream.write_all(&[0])?;
            }
            options_len += rem;
        }

        let hlen = 20 + options_len;
        let hlen = hlen / 4;
        let hlen = (0b1111_0000 & (hlen << 4)) as u8;

        stream.update_marker(&hlen_marker).write_u8(hlen)?;
        stream.write_all(&self.content)?;

        Ok(())
    }
}

impl ToBytestream for TcpFlags {
    type Error = std::io::Error;
    fn to_bytestream(&self, stream: &mut BytestreamWriter) -> Result<(), Self::Error> {
        let mut byte = 0u8;
        if self.cwr {
            byte |= 0b1000_0000;
        }
        if self.ece {
            byte |= 0b0100_0000;
        }
        if self.urg {
            byte |= 0b0010_0000;
        }
        if self.ack {
            byte |= 0b0001_0000;
        }

        if self.psh {
            byte |= 0b0000_1000;
        }
        if self.rst {
            byte |= 0b0000_0100;
        }
        if self.syn {
            byte |= 0b0000_0010;
        }
        if self.fin {
            byte |= 0b0000_0001;
        }

        stream.write_u8(byte)
    }
}

impl ToBytestream for TcpOption {
    type Error = std::io::Error;
    fn to_bytestream(&self, stream: &mut BytestreamWriter) -> Result<(), Self::Error> {
        match self {
            Self::MaximumSegmentSize(mss) => {
                stream.write_u8(2)?;
                stream.write_u8(4)?;
                stream.write_u16::<BE>(*mss)
            }
            Self::WindowScaling(cnt) => {
                stream.write_u8(3)?;
                stream.write_u8(3)?;
                stream.write_u8(*cnt)
            }
            Self::Timestamp(send, recv) => {
                stream.write_u8(8)?;
                stream.write_u8(10)?;
                stream.write_u32::<BE>(*send)?;
                stream.write_u32::<BE>(*recv)
            }
            Self::EndOfOptionsList() => stream.write_u8(0),
        }
    }
}

impl FromBytestream for TcpPacket {
    type Error = std::io::Error;
    fn from_bytestream(stream: &mut BytestreamReader) -> Result<Self, Self::Error> {
        let src_port = stream.read_u16::<BE>()?;
        let dest_port = stream.read_u16::<BE>()?;

        let seq_no = stream.read_u32::<BE>()?;
        let ack_no = stream.read_u32::<BE>()?;

        let hlen = stream.read_u8()? >> 4 & 0b1111;
        let flags = TcpFlags::from_bytestream(stream)?;
        let window = stream.read_u16::<BE>()?;

        let zero = stream.read_u16::<BE>()?;
        assert_eq!(zero, 0);
        let urgent_ptr = stream.read_u16::<BE>()?;

        let options_len = hlen * 4 - 20;
        let mut substream = stream.extract(options_len as usize)?;
        let mut options = Vec::new();
        while !substream.is_empty() {
            let option = TcpOption::from_bytestream(&mut substream)?;
            options.push(option);
            if option == TcpOption::EndOfOptionsList() {
                break;
            }
        }
        let mut content = Vec::new();
        stream.read_to_end(&mut content)?;

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
    fn from_bytestream(stream: &mut BytestreamReader) -> Result<Self, Self::Error> {
        let byte = stream.read_u8()?;

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
    fn from_bytestream(stream: &mut BytestreamReader) -> Result<Self, Self::Error> {
        let kind = stream.read_u8()?;
        if kind == 0 {
            return Ok(Self::EndOfOptionsList());
        }

        let len = stream.read_u8()? - 2;
        let mut substream = stream.extract(len as usize)?;

        match kind {
            2 => {
                let mss = substream.read_u16::<BE>()?;
                Ok(Self::MaximumSegmentSize(mss))
            }
            3 => {
                let cnt = substream.read_u8()?;
                Ok(Self::WindowScaling(cnt))
            }
            8 => {
                let send = substream.read_u32::<BE>()?;
                let recv = substream.read_u32::<BE>()?;
                Ok(Self::Timestamp(send, recv))
            }
            _ => Err(Error::new(ErrorKind::Other, "invalid tcp options kind")),
        }
    }
}
