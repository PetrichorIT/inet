use std::io::{Error, ErrorKind, Write};

use bitflags::bitflags;
use bytes_io::{
    Bytes, BytesReader, BytesWriter, FromBytes, ReadBytesExt, ToBytes, WriteBytesExt, BE,
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

    pub content: Bytes,
}

bitflags! {
    /// Flags of a [`TcpPacket`].
    #[repr(transparent)]
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TcpOption {
    EndOfOptionsList,
    NoOperation,
    MaximumSegmentSize(u16),
    WindowScaling(u8),
    SelectiveAcknowledgementPermitted,
    SelectiveAcknowledgement(Vec<(u32, u32)>),
    Timestamp(u32, u32),
}

impl TcpPacket {
    #[must_use]
    pub fn new(
        src_port: u16,
        dst_port: u16,
        seq_no: u32,
        ack_no: u32,
        window: u16,
        content: impl Into<Bytes>,
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
            content: content.into(),
        }
    }

    #[must_use]
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
            content: Bytes::new(),
        }
    }

    /// Creates a SYN+ACK for an incoming SYN
    ///
    /// # Panics
    ///
    /// This function panics if the input packet is not a SYN.
    #[must_use]
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
            content: Bytes::new(),
        }
    }

    #[must_use]
    pub fn with_mss(mut self, mss: u16) -> Self {
        self.options.insert(0, TcpOption::MaximumSegmentSize(mss));
        if self.options.last() != Some(&TcpOption::EndOfOptionsList) {
            self.options.push(TcpOption::EndOfOptionsList);
        }
        self
    }

    #[must_use]
    pub fn with_option(mut self, option: TcpOption) -> Self {
        self.options.push(option);
        self
    }

    #[must_use]
    pub fn fin(mut self, value: bool) -> Self {
        self.flags.set(TcpFlags::FIN, value);
        self
    }

    #[must_use]
    pub fn rst(seq_no: u32, window: u16, cause: &TcpPacket) -> TcpPacket {
        TcpPacket {
            src_port: cause.dst_port,
            dst_port: cause.src_port,
            seq_no,
            ack_no: 0,
            flags: TcpFlags::RST,
            window,
            urgent_ptr: 0,
            options: Vec::new(),
            content: Bytes::new(),
        }
    }

    #[must_use]
    pub fn rst_for_syn(syn: &TcpPacket) -> TcpPacket {
        TcpPacket {
            src_port: syn.dst_port,
            dst_port: syn.src_port,
            seq_no: syn.ack_no,
            ack_no: syn.seq_no.wrapping_add(1),
            flags: TcpFlags::empty().put(TcpFlags::ACK).put(TcpFlags::RST),
            window: 0,
            urgent_ptr: 0,
            options: Vec::new(),
            content: Bytes::new(),
        }
    }
}

impl TcpFlags {
    #[must_use]
    pub fn put(mut self, flag: TcpFlags) -> Self {
        self.insert(flag);
        self
    }

    #[must_use]
    pub fn putv(mut self, flag: TcpFlags, value: bool) -> Self {
        self.set(flag, value);
        self
    }
}

const TCP_OPTION_KIND_EEOL: u8 = 0;
const TCP_OPTION_KIND_NOP: u8 = 1;
const TCP_OPTION_KIND_MSS: u8 = 2;
const TCP_OPTION_KIND_WINDOWSCALE: u8 = 3;
const TCP_OPTION_KIND_SACKPERMITTED: u8 = 4;
const TCP_OPTION_KIND_SACK: u8 = 5;
const TCP_OPTION_KIND_TIMESTAMP: u8 = 8;

impl ToBytes for TcpPacket {
    type Error = std::io::Error;
    fn to_bytes(&self, stream: &mut BytesWriter) -> Result<(), Self::Error> {
        stream.write_u16::<BE>(self.src_port)?;
        stream.write_u16::<BE>(self.dst_port)?;

        stream.write_u32::<BE>(self.seq_no)?;
        stream.write_u32::<BE>(self.ack_no)?;

        let hlen_marker = stream.marker::<u8>();
        self.flags.to_bytes(stream)?;
        stream.write_u16::<BE>(self.window)?;
        stream.write_u16::<BE>(0)?;
        stream.write_u16::<BE>(self.urgent_ptr)?;

        for option in &self.options {
            option.to_bytes(stream)?;
        }

        let mut options_len = stream.bytes_written_since(&hlen_marker) - 7;
        if options_len > 0 {
            if *self.options.last().unwrap() != TcpOption::EndOfOptionsList {
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

        stream.apply(hlen_marker).write_u8(hlen)?;
        stream.write_all(&self.content)?;

        Ok(())
    }
}

impl ToBytes for TcpFlags {
    type Error = std::io::Error;
    fn to_bytes(&self, stream: &mut BytesWriter) -> Result<(), Self::Error> {
        stream.write_u8(self.bits())
    }
}

impl ToBytes for TcpOption {
    type Error = std::io::Error;
    fn to_bytes(&self, stream: &mut BytesWriter) -> Result<(), Self::Error> {
        match self {
            Self::EndOfOptionsList => stream.write_u8(TCP_OPTION_KIND_EEOL),
            Self::NoOperation => stream.write_u8(TCP_OPTION_KIND_NOP),

            Self::MaximumSegmentSize(mss) => {
                write_option_bytes(TCP_OPTION_KIND_MSS, stream, |body| {
                    body.write_u16::<BE>(*mss)
                })
            }
            Self::WindowScaling(cnt) => {
                write_option_bytes(TCP_OPTION_KIND_WINDOWSCALE, stream, |body| {
                    body.write_u8(*cnt)
                })
            }
            Self::SelectiveAcknowledgementPermitted => {
                write_option_bytes(TCP_OPTION_KIND_SACKPERMITTED, stream, |_| Ok(()))
            }
            Self::SelectiveAcknowledgement(sacks) => {
                write_option_bytes(TCP_OPTION_KIND_SACK, stream, |body| {
                    if sacks.len() > 4 {
                        return Err(Error::new(ErrorKind::InvalidInput, "too many SACK blocks"));
                    }

                    for sack in sacks {
                        body.write_u32::<BE>(sack.0)?;
                        body.write_u32::<BE>(sack.1)?;
                    }
                    Ok(())
                })
            }
            Self::Timestamp(send, recv) => {
                write_option_bytes(TCP_OPTION_KIND_TIMESTAMP, stream, |body| {
                    body.write_u32::<BE>(*send)?;
                    body.write_u32::<BE>(*recv)
                })
            }
        }
    }
}

fn write_option_bytes(
    kind: u8,
    stream: &mut BytesWriter,
    f: impl FnOnce(&mut BytesWriter) -> Result<(), std::io::Error>,
) -> Result<(), std::io::Error> {
    stream.write_u8(kind)?;
    let marker = stream.marker::<u8>();

    f(stream)?;
    let written_len = stream.bytes_written_since(&marker) + 2; // bytes for kind and len included
    stream.apply(marker).write_u8(written_len as u8)?;
    Ok(())
}

impl FromBytes for TcpPacket {
    type Error = std::io::Error;
    fn from_bytes(stream: &mut BytesReader) -> Result<Self, Self::Error> {
        let src_port = stream.read_u16::<BE>()?;
        let dst_port = stream.read_u16::<BE>()?;

        let seq_no = stream.read_u32::<BE>()?;
        let ack_no = stream.read_u32::<BE>()?;

        let hlen = stream.read_u8()? >> 4 & 0b1111;
        let flags = TcpFlags::from_bytes(stream)?;
        let window = stream.read_u16::<BE>()?;

        let zero = stream.read_u16::<BE>()?;
        assert_eq!(zero, 0);
        let urgent_ptr = stream.read_u16::<BE>()?;

        let options_len = hlen * 4 - 20;
        let options = stream.extract(options_len as usize, |substream| {
            let mut options = Vec::new();
            while substream.has_remaining() {
                let option = TcpOption::from_bytes(substream)?;
                let is_end = option == TcpOption::EndOfOptionsList;
                options.push(option);
                if is_end {
                    break;
                }
            }
            Ok(options)
        })?;

        let remaining = stream.remaining();
        let content = stream.copy_to_bytes(remaining);
        debug_assert!(!stream.has_remaining());

        Ok(TcpPacket {
            src_port,
            dst_port,
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

impl FromBytes for TcpFlags {
    type Error = std::io::Error;
    fn from_bytes(stream: &mut BytesReader) -> Result<Self, Self::Error> {
        let byte = stream.read_u8()?;
        Ok(TcpFlags::from_bits(byte).unwrap())
    }
}

impl FromBytes for TcpOption {
    type Error = std::io::Error;
    fn from_bytes(stream: &mut BytesReader) -> Result<Self, Self::Error> {
        let kind = stream.read_u8()?;

        return match kind {
            TCP_OPTION_KIND_EEOL => Ok(Self::EndOfOptionsList),
            TCP_OPTION_KIND_NOP => Ok(Self::NoOperation),

            TCP_OPTION_KIND_MSS => read_option_bytes(stream, |body| {
                Ok(TcpOption::MaximumSegmentSize(body.read_u16::<BE>()?))
            }),
            TCP_OPTION_KIND_WINDOWSCALE => {
                read_option_bytes(stream, |body| Ok(TcpOption::WindowScaling(body.read_u8()?)))
            }
            TCP_OPTION_KIND_SACKPERMITTED => read_option_bytes(stream, |body| {
                debug_assert!(!body.has_remaining());
                Ok(TcpOption::SelectiveAcknowledgementPermitted)
            }),
            TCP_OPTION_KIND_SACK => read_option_bytes(stream, |body| {
                let mut sacks = Vec::new();
                while body.has_remaining() {
                    let start = body.read_u32::<BE>()?;
                    let end = body.read_u32::<BE>()?;
                    sacks.push((start, end));
                }

                Ok(TcpOption::SelectiveAcknowledgement(sacks))
            }),
            TCP_OPTION_KIND_TIMESTAMP => read_option_bytes(stream, |body| {
                Ok(TcpOption::Timestamp(
                    body.read_u32::<BE>()?,
                    body.read_u32::<BE>()?,
                ))
            }),
            _ => Err(Error::new(ErrorKind::Other, "invalid tcp options kind")),
        };
    }
}

fn read_option_bytes(
    stream: &mut BytesReader,
    f: fn(&mut BytesReader) -> Result<TcpOption, std::io::Error>,
) -> Result<TcpOption, std::io::Error> {
    let len = stream.read_u8()? - 2;
    stream.extract(len as usize, f)
}

#[cfg(test)]
mod tests {
    use bytes_io::assert_encoding_e2e;
    use rand::{rng, Rng};

    use super::*;

    #[test]
    fn e2e_encoding_fuzz() {
        let fuzzed = std::iter::repeat_with(|| TcpPacket {
            src_port: rng().random(),
            dst_port: rng().random(),
            seq_no: rng().random(),
            ack_no: rng().random(),
            flags: TcpFlags::from_bits(rng().random()).unwrap(),
            window: rng().random(),
            urgent_ptr: rng().random(),
            options: Vec::new(),
            content: std::iter::repeat_with(|| rng().random())
                .take((rng().random::<u32>() % 1500) as usize)
                .collect(),
        })
        .take(100)
        .collect::<Vec<_>>();

        assert_encoding_e2e(&fuzzed);
    }

    #[test]
    fn e2e_encoding_options() {
        assert_encoding_e2e(&[
            TcpOption::WindowScaling(2),
            TcpOption::WindowScaling(8),
            TcpOption::Timestamp(132313, 441),
            TcpOption::SelectiveAcknowledgementPermitted,
            TcpOption::SelectiveAcknowledgement(vec![(32, 3), (3123, 4)]),
            TcpOption::NoOperation,
            TcpOption::MaximumSegmentSize(12333),
            TcpOption::MaximumSegmentSize(4133),
            TcpOption::EndOfOptionsList,
        ]);
    }
}
