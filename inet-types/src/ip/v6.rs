use bytepack::{
    BytestreamReader, BytestreamWriter, FromBytestream, ReadBytesExt, ToBytestream, WriteBytesExt,
    BE,
};
use des::net::message::MessageBody;
use std::{
    io::{Error, ErrorKind, Read, Write},
    net::Ipv6Addr,
};

pub const IPV6_LINK_LOCAL: Ipv6Addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0);
pub const IPV6_MULTICAST_ALL_ROUTERS: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 2);
pub const IPV6_MULTICAST_ALL_NODES: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Ipv6Packet {
    pub traffic_class: u8,
    pub flow_label: u32, // u20
    pub next_header: u8,
    pub hop_limit: u8,

    pub src: Ipv6Addr,
    pub dst: Ipv6Addr,

    pub content: Vec<u8>,
}

impl ToBytestream for Ipv6Packet {
    type Error = std::io::Error;
    fn to_bytestream(&self, stream: &mut BytestreamWriter) -> Result<(), Self::Error> {
        let header = (6 << 4) | (self.traffic_class >> 4);
        stream.write_u8(header)?;

        let bytes = self.flow_label.to_be_bytes();
        let byte_0 = ((self.traffic_class & 0b1111) << 4) | bytes[1] & 0b1111;
        stream.write_u8(byte_0)?;
        stream.write_u8(bytes[2])?;
        stream.write_u8(bytes[3])?;

        let len = self.content.len() as u16;
        stream.write_u16::<BE>(len)?;
        stream.write_u8(self.next_header)?;
        stream.write_u8(self.hop_limit)?;

        stream.write_all(&self.src.octets())?;
        stream.write_all(&self.dst.octets())?;

        stream.write_all(&self.content)?;
        Ok(())
    }
}

impl FromBytestream for Ipv6Packet {
    type Error = std::io::Error;
    fn from_bytestream(stream: &mut BytestreamReader) -> Result<Self, Self::Error> {
        let byte0 = stream.read_u8()?;
        let byte1 = stream.read_u8()?;
        let byte2 = stream.read_u8()?;
        let byte3 = stream.read_u8()?;

        let version = byte0 >> 4;
        if version != 6 {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "ipv6 packet expeced, got ipv4 flag",
            ));
        }

        // println!("{:b} {:b} {:b} {:b}", byte0, byte1, byte2, byte3);
        let traffic_class = ((byte0 & 0b1111) << 4) | ((byte1 >> 4) & 0b1111);

        let f2 = byte1 & 0b1111;
        let flow_label = u32::from_be_bytes([0, f2, byte2, byte3]);

        let len = stream.read_u16::<BE>()?;
        let next_header = stream.read_u8()?;
        let hop_limit = stream.read_u8()?;

        let src = Ipv6Addr::from(stream.read_u128::<BE>()?);
        let dest = Ipv6Addr::from(stream.read_u128::<BE>()?);

        // fetch rest
        let mut content = vec![0; len as usize];
        stream.read_exact(&mut content)?;

        Ok(Self {
            traffic_class,
            flow_label,
            next_header,
            hop_limit,
            src,
            dst: dest,
            content,
        })
    }
}

impl MessageBody for Ipv6Packet {
    fn byte_len(&self) -> usize {
        40 + self.content.len()
    }
}

pub fn ipv6_solicited_node_multicast(addr: Ipv6Addr) -> Ipv6Addr {
    let mut bytes = [0; 16];
    bytes[0] = 0xff;
    bytes[1] = 0x02;
    // pad
    bytes[11] = 0x01;
    bytes[12] = 0xff;
    bytes[13..].copy_from_slice(&mut addr.octets()[13..]);
    Ipv6Addr::from(bytes)
}
