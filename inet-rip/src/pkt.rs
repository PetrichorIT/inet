use bytepack::raw_enum;
use bytepack::{
    ByteOrder::BigEndian, BytestreamReader, BytestreamWriter, FromBytestream, StreamReader,
    StreamWriter, ToBytestream,
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
    fn to_bytestream(&self, bytestream: &mut BytestreamWriter) -> Result<(), Self::Error> {
        self.command.to_bytestream(bytestream)?;
        2u8.write_to(bytestream, BigEndian)?;
        0u16.write_to(bytestream, BigEndian)?;
        for entry in &self.entries {
            entry.to_bytestream(bytestream)?;
        }
        Ok(())
    }
}

impl FromBytestream for RipPacket {
    type Error = Error;
    fn from_bytestream(bytestream: &mut BytestreamReader) -> Result<Self, Self::Error> {
        let command = RipCommand::from_bytestream(bytestream)?;
        let version = u8::read_from(bytestream, BigEndian)?;
        assert_eq!(version, 2);
        assert_eq!(0, u16::read_from(bytestream, BigEndian)?);

        let mut entries = Vec::new();
        while !bytestream.is_empty() {
            entries.push(RipEntry::from_bytestream(bytestream)?);
        }
        Ok(RipPacket { command, entries })
    }
}

pub const AF_INET: u16 = 2;

impl ToBytestream for RipEntry {
    type Error = Error;
    fn to_bytestream(&self, bytestream: &mut BytestreamWriter) -> Result<(), Self::Error> {
        self.addr_fam.write_to(bytestream, BigEndian)?;
        0u16.write_to(bytestream, BigEndian)?;
        u32::from(self.target).write_to(bytestream, BigEndian)?;
        u32::from(self.mask).write_to(bytestream, BigEndian)?;
        u32::from(self.next_hop).write_to(bytestream, BigEndian)?;
        self.metric.write_to(bytestream, BigEndian)?;

        Ok(())
    }
}

impl FromBytestream for RipEntry {
    type Error = Error;
    fn from_bytestream(bytestream: &mut BytestreamReader) -> Result<Self, Self::Error> {
        let addr_fam = u16::read_from(bytestream, BigEndian)?;
        assert_eq!(0, u16::read_from(bytestream, BigEndian)?);
        let target = Ipv4Addr::from(u32::read_from(bytestream, BigEndian)?);
        let mask = Ipv4Addr::from(u32::read_from(bytestream, BigEndian)?);
        let next_hop = Ipv4Addr::from(u32::read_from(bytestream, BigEndian)?);
        let metric = u32::read_from(bytestream, BigEndian)?;

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

        let buf = pkt.to_buffer()?;
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
        let buf = rip.to_buffer()?;
        assert_eq!(buf.len(), 4 + 20 * 20);
        let rip2 = RipPacket::from_slice(&buf)?;
        assert_eq!(rip, rip2);

        Ok(())
    }
}
