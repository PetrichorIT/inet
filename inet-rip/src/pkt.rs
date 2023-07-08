use bytepack::raw_enum;
use bytepack::{
    BytestreamReader, BytestreamWriter, FromBytestream, ReadBytesExt, ToBytestream, WriteBytesExt,
    BE,
};
use std::{io::Error, net::Ipv4Addr};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RipPacket {
    pub command: RipCommand,
    // pub version: u8
    pub entries: Vec<RipEntry>,
}

raw_enum! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub enum RipCommand {
        type Repr = u8 where BigEndian;
        Request = 1,
        Response = 2,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RipEntry {
    pub addr_fam: u16,
    pub target: Ipv4Addr,
    pub mask: Ipv4Addr,
    pub next_hop: Ipv4Addr,
    pub metric: u32,
}

impl RipPacket {
    pub fn packets(command: RipCommand, mut entries: &[RipEntry]) -> Vec<RipPacket> {
        let mut r = Vec::with_capacity(entries.len() / 25 + 1);
        while !entries.is_empty() {
            let mut pkt = RipPacket {
                command,
                entries: Vec::with_capacity(entries.len().min(25)),
            };
            pkt.entries.extend(&entries[..25.min(entries.len())]);
            entries = &entries[pkt.entries.len()..];
            r.push(pkt);
        }
        r
    }
}

impl ToBytestream for RipPacket {
    type Error = Error;
    fn to_bytestream(&self, stream: &mut BytestreamWriter) -> Result<(), Self::Error> {
        stream.write_u8(self.command.to_raw_repr())?;
        stream.write_u8(2)?;
        stream.write_u16::<BE>(0)?;
        for entry in &self.entries {
            entry.to_bytestream(stream)?;
        }
        Ok(())
    }
}

impl FromBytestream for RipPacket {
    type Error = Error;
    fn from_bytestream(stream: &mut BytestreamReader) -> Result<Self, Self::Error> {
        let command = RipCommand::from_raw_repr(stream.read_u8()?)?;
        let version = stream.read_u8()?;
        assert_eq!(version, 2);
        assert_eq!(0, stream.read_u16::<BE>()?);

        let mut entries = Vec::new();
        while !stream.is_empty() {
            entries.push(RipEntry::from_bytestream(stream)?);
        }
        Ok(RipPacket { command, entries })
    }
}

pub const AF_INET: u16 = 2;

impl ToBytestream for RipEntry {
    type Error = Error;
    fn to_bytestream(&self, stream: &mut BytestreamWriter) -> Result<(), Self::Error> {
        stream.write_u16::<BE>(self.addr_fam)?;
        stream.write_u16::<BE>(0)?;

        stream.write_u32::<BE>(u32::from(self.target))?;
        stream.write_u32::<BE>(u32::from(self.mask))?;
        stream.write_u32::<BE>(u32::from(self.next_hop))?;
        stream.write_u32::<BE>(self.metric)?;
        Ok(())
    }
}

impl FromBytestream for RipEntry {
    type Error = Error;
    fn from_bytestream(stream: &mut BytestreamReader) -> Result<Self, Self::Error> {
        let addr_fam = stream.read_u16::<BE>()?;
        assert_eq!(0, stream.read_u16::<BE>()?);
        let target = Ipv4Addr::from(stream.read_u32::<BE>()?);
        let mask = Ipv4Addr::from(stream.read_u32::<BE>()?);
        let next_hop = Ipv4Addr::from(stream.read_u32::<BE>()?);
        let metric = stream.read_u32::<BE>()?;

        Ok(Self {
            addr_fam,
            target,
            mask,
            next_hop,
            metric,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Result;

    #[test]
    fn single_entry_encoding() -> Result<()> {
        let pkt = RipPacket {
            command: RipCommand::Response,
            entries: vec![RipEntry {
                addr_fam: AF_INET,
                target: Ipv4Addr::new(1, 2, 3, 4),
                mask: Ipv4Addr::new(255, 255, 255, 0),
                next_hop: Ipv4Addr::UNSPECIFIED,
                metric: 1003,
            }],
        };

        let buf = pkt.to_vec()?;
        assert_eq!(
            buf,
            &[
                0x02, 0x02, 0x00, 0x00, // header
                0x00, 0x02, 0x00, 0x00, // addr_fam
                0x01, 0x02, 0x03, 0x04, // ip,
                0xff, 0xff, 0xff, 0x00, // mask
                0x00, 0x00, 0x00, 0x00, // pad #2.
                0x00, 0x00, 0x03, 0xeb, // metrics
            ]
        );

        Ok(())
    }

    #[test]
    fn single_entry_decoding() -> Result<()> {
        let buf = &[
            0x01, 0x02, 0x00, 0x00, // header
            0x00, 0x02, 0x00, 0x00, // addr_fam
            0x06, 0x07, 0x08, 0x09, // ip,
            0x00, 0x00, 0x00, 0x00, // pad #1
            0x00, 0x00, 0x00, 0x00, // pad #2.
            0x00, 0x00, 0x03, 0xeb, // metrics
        ];

        let pkt = RipPacket::from_slice(buf)?;

        assert_eq!(
            pkt,
            RipPacket {
                command: RipCommand::Request,
                entries: vec![RipEntry {
                    addr_fam: AF_INET,
                    target: Ipv4Addr::new(6, 7, 8, 9),
                    mask: Ipv4Addr::UNSPECIFIED,
                    next_hop: Ipv4Addr::UNSPECIFIED,
                    metric: 1003
                }],
            }
        );

        Ok(())
    }

    #[test]
    fn multi_entry_stream() -> Result<()> {
        let entries = (1..=20)
            .map(|i| RipEntry {
                addr_fam: AF_INET,
                target: Ipv4Addr::new(i as u8, (i * 2) as u8, ((i * i) % 256) as u8, i as u8 / 2),
                mask: Ipv4Addr::from(i),
                next_hop: Ipv4Addr::UNSPECIFIED,
                metric: i * i ^ 0xaa571b,
            })
            .collect::<Vec<_>>();

        let rip = RipPacket {
            command: RipCommand::Request,
            entries,
        };
        let buf = rip.to_vec()?;
        assert_eq!(buf.len(), 4 + 20 * 20);
        let rip2 = RipPacket::from_slice(&buf)?;
        assert_eq!(rip, rip2);

        Ok(())
    }
}
