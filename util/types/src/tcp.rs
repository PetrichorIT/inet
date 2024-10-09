use std::io::{Error, ErrorKind, Read, Write};

use bitflags::bitflags;
use bytepack::{
    BytestreamReader, BytestreamWriter, FromBytestream, ReadBytesExt, ToBytestream, WriteBytesExt,
    BE,
};

pub const PROTO_TCP: u8 = 0x06;

/// A TCP packet assosciated with an end-to-end connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpPacket {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq_no: u32,
    pub ack_no: u32,
    pub flags: TcpFlags,
    pub window: u16,
    pub urgent_ptr: u16,
    pub options: Vec<TcpOption>,

    pub content: Vec<u8>,
}

bitflags! {
    /// Flags of a [`TcpPacket`].
    pub struct TcpFlags: u8 {
        const CWR = 0b1000_0000;
        const ECE = 0b0100_0000;
        const URG = 0b0010_0000;
        const ACK = 0b0001_0000;
        const PSH = 0b0000_1000;
        const RST = 0b0000_0100;
        const SYN = 0b0000_0010;
        const FIN = 0b0000_0001;
    }
}

/// Options of a [`TcpPacket`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TcpOption {
    MaximumSegmentSize(u16),
    WindowScaling(u8),
    Timestamp(u32, u32),
    EndOfOptionsList(),
}

impl TcpPacket {
    pub fn new(
        src_port: u16,
        dst_port: u16,
        seq_no: u32,
        ack_no: u32,
        window: u16,
        content: Vec<u8>,
    ) -> TcpPacket {
        TcpPacket {
            src_port,
            dst_port,
            seq_no,
            ack_no,
            flags: TcpFlags::empty().put(TcpFlags::ACK),
            window,
            urgent_ptr: 0,
            options: Vec::new(),
            content,
        }
    }

    pub fn syn(src_port: u16, dst_port: u16, seq_no: u32, window: u16) -> TcpPacket {
        TcpPacket {
            src_port,
            dst_port,
            seq_no,
            ack_no: 0,
            flags: TcpFlags::empty().put(TcpFlags::SYN),
            window,
            urgent_ptr: 0,
            options: Vec::new(),
            content: Vec::new(),
        }
    }

    pub fn syn_ack(syn: &TcpPacket, seq_no: u32, window: u16) -> TcpPacket {
        assert!(syn.flags.contains(TcpFlags::SYN));
        TcpPacket {
            src_port: syn.dst_port,
            dst_port: syn.src_port,
            seq_no,
            ack_no: syn.seq_no.wrapping_add(1),
            flags: TcpFlags::empty().put(TcpFlags::SYN).put(TcpFlags::ACK),
            window,
            urgent_ptr: 0,
            options: Vec::new(),
            content: Vec::new(),
        }
    }

    pub fn with_mss(mut self, mss: u16) -> Self {
        self.options.insert(0, TcpOption::MaximumSegmentSize(mss));
        if self.options.last() != Some(&TcpOption::EndOfOptionsList()) {
            self.options.push(TcpOption::EndOfOptionsList());
        }
        self
    }

    pub fn fin(mut self, value: bool) -> Self {
        self.flags.set(TcpFlags::FIN, value);
        self
    }

    #[must_use]
    pub fn rst_for_syn(syn: &TcpPacket) -> TcpPacket {
        TcpPacket {
            src_port: syn.dst_port,
            dst_port: syn.src_port,
            seq_no: 0,
            ack_no: syn.seq_no,
            flags: TcpFlags::empty().put(TcpFlags::ACK).put(TcpFlags::RST),
            window: 0,
            urgent_ptr: 0,
            options: Vec::new(),
            content: Vec::new(),
        }
    }
}

impl TcpFlags {
    pub fn put(mut self, flag: TcpFlags) -> Self {
        self.insert(flag);
        self
    }

    pub fn putv(mut self, flag: TcpFlags, value: bool) -> Self {
        self.set(flag, value);
        self
    }
}

impl ToBytestream for TcpPacket {
    type Error = std::io::Error;
    fn to_bytestream(&self, stream: &mut BytestreamWriter) -> Result<(), Self::Error> {
        stream.write_u16::<BE>(self.src_port)?;
        stream.write_u16::<BE>(self.dst_port)?;

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
        stream.write_u8(self.bits())
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
            dst_port: dest_port,
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
        Ok(TcpFlags::from_bits(byte).unwrap())
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
