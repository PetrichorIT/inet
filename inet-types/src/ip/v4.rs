use bytepack::{
    BytestreamReader, BytestreamWriter, FromBytestream, ReadBytesExt, ToBytestream, WriteBytesExt,
    BE,
};
use des::net::message::MessageBody;
use std::{
    io::{Error, ErrorKind, Read, Write},
    net::Ipv4Addr,
};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Ipv4Packet {
    // pub version: IpVersion,
    pub dscp: u8, // prev tos
    pub enc: u8,
    pub identification: u16,
    pub flags: Ipv4Flags,
    pub fragment_offset: u16,
    pub ttl: u8,
    pub proto: u8,
    // pub checksum: u16,
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,

    pub content: Vec<u8>,
}

impl Ipv4Packet {
    pub const EMPTY: Ipv4Packet = Ipv4Packet {
        dscp: 0,
        enc: 0,
        identification: 0,
        flags: Ipv4Flags {
            df: false,
            mf: false,
        },
        fragment_offset: 0,
        ttl: 64,
        proto: 0,
        src: Ipv4Addr::UNSPECIFIED,
        dst: Ipv4Addr::UNSPECIFIED,
        content: Vec::new(),
    };

    pub fn reverse(&self) -> Ipv4Packet {
        Ipv4Packet {
            dscp: self.dscp,
            enc: self.enc,
            identification: self.identification,
            flags: Ipv4Flags {
                df: self.flags.df,
                mf: false,
            },
            fragment_offset: 0,
            ttl: 64,
            proto: self.proto,
            src: self.dst,
            dst: self.src,
            content: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ipv4Flags {
    pub df: bool,
    pub mf: bool,
}

impl Ipv4Flags {
    fn as_u16(self) -> u16 {
        let pat = (if self.df { 0b010u16 } else { 0u16 } | if self.mf { 0b100u16 } else { 0u16 });
        pat << 13u16
    }
}

impl ToBytestream for Ipv4Packet {
    type Error = std::io::Error;
    fn to_bytestream(&self, stream: &mut BytestreamWriter) -> Result<(), Self::Error> {
        stream.write_u8(0b0100_0101)?;
        stream.write_u8((self.dscp << 2) | self.enc)?;

        let len = 20 + self.content.len() as u16;
        stream.write_u16::<BE>(len)?;
        stream.write_u16::<BE>(self.identification)?;

        let fbyte = self.flags.as_u16() | self.fragment_offset;
        stream.write_u16::<BE>(fbyte)?;

        stream.write_u8(self.ttl)?;
        stream.write_u8(self.proto)?;
        stream.write_u16::<BE>(0)?;

        stream.write_all(&self.src.octets())?;
        stream.write_all(&self.dst.octets())?;

        stream.write_all(&self.content)?;
        Ok(())
    }
}

impl FromBytestream for Ipv4Packet {
    type Error = std::io::Error;
    fn from_bytestream(stream: &mut BytestreamReader) -> Result<Self, Self::Error> {
        let byte0 = stream.read_u8()?;
        let version = byte0 >> 4;
        if version != 4 {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "Ipv4 version flag expected, got other value",
            ));
        }

        // let ihl = byte0 & 0x0f;

        let byte1 = stream.read_u8()?;
        let dscp = byte1 >> 2;
        let enc = byte1 & 0x03;

        let len = stream.read_u16::<BE>()?;
        let identification = stream.read_u16::<BE>()?;

        let fword = stream.read_u16::<BE>()?;
        let flags = {
            let fbyte = fword >> 13;
            let mut flags = Ipv4Flags {
                mf: false,
                df: false,
            };
            if fbyte & 0b100 != 0 {
                flags.mf = true;
            }
            if fbyte & 0b010 != 0 {
                flags.df = true;
            }
            flags
        };
        let fragment_offset = fword & 0x1fff;

        let ttl = stream.read_u8()?;
        let proto = stream.read_u8()?;

        let _checksum = stream.read_u16::<BE>()?;
        // TODO: check checksum

        let src = Ipv4Addr::from(stream.read_u32::<BE>()?);
        let dest = Ipv4Addr::from(stream.read_u32::<BE>()?);

        // fetch rest
        let mut content = vec![0; len as usize - 20];
        stream.read_exact(&mut content)?;

        Ok(Self {
            // ihl,
            dscp,
            enc,
            // len,
            identification,
            flags,
            fragment_offset,
            ttl,
            proto,
            src,
            dst: dest,
            content,
        })
    }
}

impl MessageBody for Ipv4Packet {
    fn byte_len(&self) -> usize {
        20 + self.content.len()
    }
}
