use bytepack::{
    ByteOrder::BigEndian, BytestreamReader, BytestreamWriter, FromBytestream, StreamReader,
    StreamWriter, ToBytestream,
};
use des::prelude::MessageBody;
use std::{
    io::{Error, ErrorKind},
    net::Ipv6Addr,
};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Ipv6Header {
    pub traffic_class: u8,
    pub flow_label: u32, // u20
    pub next_header: u8,
    pub hop_limit: u8,
    pub len: u16,

    pub src: Ipv6Addr,
    pub dest: Ipv6Addr,
}

impl Ipv6Header {
    pub fn reverse(&self) -> Ipv6Header {
        Ipv6Header {
            traffic_class: self.traffic_class,
            flow_label: self.flow_label,
            next_header: self.next_header,
            hop_limit: 64,
            len: 0,
            src: self.dest,
            dest: self.src,
        }
    }
}

impl ToBytestream for Ipv6Header {
    type Error = std::io::Error;
    fn to_bytestream(&self, bytestream: &mut BytestreamWriter) -> Result<(), Self::Error> {
        let header = (6 << 4) | (self.traffic_class >> 4);
        header.write_to(bytestream, BigEndian)?;

        // [32..24 24..16 16..8 8..0]
        let bytes = self.flow_label.to_be_bytes();
        let byte_0 = ((self.traffic_class & 0b1111) << 4) | bytes[1] & 0b1111;
        byte_0.write_to(bytestream, BigEndian)?;
        bytes[2].write_to(bytestream, BigEndian)?;
        bytes[3].write_to(bytestream, BigEndian)?;

        self.len.write_to(bytestream, BigEndian)?;
        self.next_header.write_to(bytestream, BigEndian)?;
        self.hop_limit.write_to(bytestream, BigEndian)?;

        for byte in self.src.octets() {
            byte.write_to(bytestream, BigEndian)?;
        }
        for byte in self.dest.octets() {
            byte.write_to(bytestream, BigEndian)?;
        }
        Ok(())
    }
}

impl FromBytestream for Ipv6Header {
    type Error = std::io::Error;
    fn from_bytestream(bytestream: &mut BytestreamReader) -> Result<Self, Self::Error> {
        let byte0 = u8::read_from(bytestream, BigEndian)?;
        let byte1 = u8::read_from(bytestream, BigEndian)?;
        let byte2 = u8::read_from(bytestream, BigEndian)?;
        let byte3 = u8::read_from(bytestream, BigEndian)?;

        let version = byte0 >> 4;
        match version {
            6 => {}
            5 => {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    "ipv6 packet expeced, got ipv4 flag",
                ))
            }
            _ => unimplemented!(),
        };

        // println!("{:b} {:b} {:b} {:b}", byte0, byte1, byte2, byte3);
        let traffic_class = ((byte0 & 0b1111) << 4) | ((byte1 >> 4) & 0b1111);

        let f2 = byte1 & 0b1111;
        let flow_label = u32::from_be_bytes([0, f2, byte2, byte3]);

        let len = u16::read_from(bytestream, BigEndian)?;
        let next_header = u8::read_from(bytestream, BigEndian)?;
        let hop_limit = u8::read_from(bytestream, BigEndian)?;

        let mut src = [0u8; 16];
        let mut dest = [0u8; 16];
        for item in &mut src {
            *item = u8::read_from(bytestream, BigEndian)?;
        }
        for item in &mut dest {
            *item = u8::read_from(bytestream, BigEndian)?;
        }

        let src = Ipv6Addr::from(src);
        let dest = Ipv6Addr::from(dest);

        Ok(Self {
            traffic_class,
            flow_label,
            next_header,
            hop_limit,
            len,
            src,
            dest,
        })
    }
}

impl MessageBody for Ipv6Header {
    fn byte_len(&self) -> usize {
        40
    }
}
