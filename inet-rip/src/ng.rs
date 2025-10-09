use std::{
    io::{Error, ErrorKind},
    net::Ipv6Addr,
};

use bytes_io::{BE, BytesWriter, FromBytes, ReadBytesExt, ToBytes, WriteBytesExt};
use inet::types::ip::Ipv6Prefix;

use crate::RipCommand;

#[derive(Debug, PartialEq, Eq)]
pub struct RipNgPacket {
    pub command: RipCommand,
    pub entries: Vec<RipNgEntry>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct RipNgEntry {
    pub prefix: Ipv6Prefix,
    pub next_hop: Ipv6Addr,
    pub tag: u16,
    pub metrics: u8,
}

impl RipNgEntry {
    pub const fn is_next_hop_entry(&self) -> bool {
        self.metrics == 0xff
    }
}

const VERSION: u8 = 1;

impl ToBytes for RipNgPacket {
    type Error = std::io::Error;
    fn to_bytes(&self, writer: &mut BytesWriter) -> Result<(), Self::Error> {
        writer.write_u8(self.command.to_raw_repr())?;
        writer.write_u8(VERSION)?;
        writer.write_u16::<BE>(0)?;

        let mut last_hop = Ipv6Addr::UNSPECIFIED;
        for entry in &self.entries {
            // Insert next_hop header if required
            if entry.next_hop != last_hop {
                last_hop = entry.next_hop;
                entry.next_hop.to_bytes(writer)?;
                writer.write_u32::<BE>(0x00_00_00_ff)?;
            }

            entry.to_bytes(writer)?;
        }

        Ok(())
    }
}

impl ToBytes for RipNgEntry {
    type Error = std::io::Error;
    fn to_bytes(&self, writer: &mut BytesWriter) -> Result<(), Self::Error> {
        self.prefix.addr().to_bytes(writer)?;
        writer.write_u16::<BE>(self.tag)?;
        writer.write_u8(self.prefix.len())?;
        writer.write_u8(self.metrics)?;
        Ok(())
    }
}

impl FromBytes for RipNgPacket {
    type Error = std::io::Error;
    fn from_bytes(stream: &mut bytes_io::BytesReader) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        let command = RipCommand::from_raw_repr(stream.read_u8()?)?;
        let version = stream.read_u8()?;
        if version != VERSION {
            return Err(Error::new(ErrorKind::InvalidData, "unsupported version"));
        }
        if stream.read_u16::<BE>()? != 0 {
            return Err(Error::new(ErrorKind::InvalidData, "reserved"));
        }

        let mut last_hop = Ipv6Addr::UNSPECIFIED;
        let mut entries = Vec::with_capacity(stream.remaining() / 20);
        while stream.has_remaining() {
            let mut entry = RipNgEntry::from_bytes(stream)?;
            if entry.is_next_hop_entry() {
                last_hop = entry.prefix.addr();
            } else {
                entry.next_hop = last_hop;
                entries.push(entry);
            }
        }

        Ok(Self { command, entries })
    }
}

impl FromBytes for RipNgEntry {
    type Error = std::io::Error;
    fn from_bytes(stream: &mut bytes_io::BytesReader) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        let addr = Ipv6Addr::from_bytes(stream)?;
        let tag = stream.read_u16::<BE>()?;
        let prefix_len = stream.read_u8()?;
        let metrics = stream.read_u8()?;
        Ok(Self {
            prefix: Ipv6Prefix::new(addr, prefix_len),
            next_hop: Ipv6Addr::UNSPECIFIED,
            tag,
            metrics,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::fs::File;

    use bytes_io::assert_encoding_e2e;
    use inet::types::{
        ip::{Ipv6Packet, KIND_IPV6},
        udp::{PROTO_UDP, UdpPacket},
    };
    use pcapng::{BlockWriter, DefaultBlockWriter, Linktype};
    use rand::{Rng, rng};

    use super::*;

    impl RipNgPacket {
        fn random_no_next_hop() -> Self {
            Self {
                command: RipCommand::from_raw_repr(1 + (rng().random::<u8>() % 2)).unwrap(),
                entries: std::iter::repeat_with(RipNgEntry::random_no_next_hop)
                    .take(16)
                    .collect(),
            }
        }
        fn random_next_hop() -> Self {
            Self {
                command: RipCommand::from_raw_repr(1 + (rng().random::<u8>() % 2)).unwrap(),
                entries: std::iter::repeat_with(RipNgEntry::random_next_hop)
                    .take(12)
                    .collect(),
            }
        }
    }

    impl RipNgEntry {
        fn random_no_next_hop() -> Self {
            Self {
                prefix: Ipv6Prefix::new(rng().random::<u128>().into(), rng().random::<u8>() % 128),
                next_hop: Ipv6Addr::UNSPECIFIED,
                tag: rng().random(),
                metrics: rng().random::<u8>() % 32,
            }
        }

        fn random_next_hop() -> Self {
            Self {
                prefix: Ipv6Prefix::new(rng().random::<u128>().into(), rng().random::<u8>() % 128),
                next_hop: Ipv6Addr::UNSPECIFIED,
                tag: rng().random(),
                metrics: rng().random::<u8>() % 32,
            }
        }
    }

    #[test]
    fn encoding_e2e() {
        let no_next_hop = std::iter::repeat_with(RipNgPacket::random_no_next_hop)
            .take(100)
            .collect::<Vec<_>>();
        assert_encoding_e2e(&no_next_hop);

        let next_hop = std::iter::repeat_with(RipNgPacket::random_next_hop)
            .take(100)
            .collect::<Vec<_>>();
        assert_encoding_e2e(&next_hop);
    }

    #[test]
    fn a() {
        let mut w =
            DefaultBlockWriter::<_, ()>::new(File::create("ripng.pcap").unwrap(), "main").unwrap();

        w.add_interface(&(), Linktype::ETHERNET, 4096, Vec::new())
            .unwrap();

        w.add_packet(
            &(),
            0,
            [1, 2, 3, 4, 5, 6],
            [2, 3, 4, 5, 6, 7],
            KIND_IPV6,
            &Ipv6Packet {
                traffic_class: 0,
                flow_label: 0,
                extension_headers: Vec::new(),
                proto: PROTO_UDP,
                src: "2003:a:1::1".parse().unwrap(),
                dst: "2003:b:1::1".parse().unwrap(),
                hop_limit: 64,
                content: UdpPacket::new(
                    512,
                    512,
                    RipNgPacket {
                        command: RipCommand::Response,
                        entries: vec![
                            RipNgEntry {
                                prefix: "2003:a:1::/64".parse().unwrap(),
                                next_hop: Ipv6Addr::UNSPECIFIED,
                                tag: 0,
                                metrics: 1,
                            },
                            RipNgEntry {
                                prefix: "2003:a:1::/64".parse().unwrap(),
                                next_hop: "2004::1".parse().unwrap(),
                                tag: 0,
                                metrics: 1,
                            },
                        ],
                    }
                    .write_to_bytes()
                    .unwrap(),
                )
                .write_to_bytes()
                .unwrap(),
            },
            None,
        )
        .unwrap();
    }
}
