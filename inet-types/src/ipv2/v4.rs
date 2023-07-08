use bytepack::{
    ByteOrder::BigEndian, BytestreamReader, BytestreamWriter, FromBytestream, StreamReader,
    StreamWriter, ToBytestream,
};
use des::prelude::MessageBody;
use std::io::{Error, ErrorKind};
use std::net::Ipv4Addr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv4Header {
    // pub version: IpVersion,
    pub dscp: u8, // prev tos
    pub len: u16,
    pub enc: u8,

    pub identification: u16,
    pub flags: u8, // u2
    pub fragment_offset: u16,

    pub ttl: u8,
    pub proto: u8,
    // pub checksum: u16,
    pub src: Ipv4Addr,
    pub dest: Ipv4Addr,
}

impl Ipv4Header {
    pub fn reverse(&self) -> Ipv4Header {
        Ipv4Header {
            dscp: self.dscp,
            enc: self.enc,
            len: 0,
            identification: self.identification,
            flags: self.flags,
            fragment_offset: 0,
            ttl: 64,
            proto: self.proto,
            src: self.dest,
            dest: self.src,
        }
    }
}

impl ToBytestream for Ipv4Header {
    type Error = std::io::Error;
    fn to_bytestream(&self, bytestream: &mut BytestreamWriter) -> Result<(), Self::Error> {
        let byte0 = 0b0100_0101u8;
        byte0.write_to(bytestream, BigEndian)?;

        // check values in bounds
        if self.dscp > 0b111111 {
            return Err(Error::new(
                ErrorKind::Other,
                "Ipv4 DSCP out of bounds (6 bit field)",
            ));
        }

        if self.enc > 0b11 {
            return Err(Error::new(
                ErrorKind::Other,
                "Ipv4 ENC out of bounds (2 bit field)",
            ));
        }

        let byte1 = (self.dscp << 2) | self.enc;
        byte1.write_to(bytestream, BigEndian)?;

        self.len.write_to(bytestream, BigEndian)?;
        self.identification.write_to(bytestream, BigEndian)?;

        if self.flags > 0b11 {
            return Err(Error::new(
                ErrorKind::Other,
                "Ipv4 flags out of bounds (2 bit field)",
            ));
        }

        if self.fragment_offset > 0x1fff {
            return Err(Error::new(
                ErrorKind::Other,
                "Ipv4 fragment offset out of bounds (13 bit field)",
            ));
        }

        let fbyte = (self.flags as u16) << 13 | self.fragment_offset;
        fbyte.write_to(bytestream, BigEndian)?;

        self.ttl.write_to(bytestream, BigEndian)?;
        self.proto.write_to(bytestream, BigEndian)?;

        // TODO: make checksum
        0u16.write_to(bytestream, BigEndian)?;

        u32::from_be_bytes(self.src.octets()).write_to(bytestream, BigEndian)?;
        u32::from_be_bytes(self.dest.octets()).write_to(bytestream, BigEndian)?;

        Ok(())
    }
}

impl FromBytestream for Ipv4Header {
    type Error = std::io::Error;
    fn from_bytestream(bytestream: &mut BytestreamReader) -> Result<Self, Self::Error> {
        let byte0 = u8::read_from(bytestream, BigEndian)?;
        let version = byte0 >> 4;
        match version {
            4 => {}
            6 => {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    "ipv4 packet expeced, got ipv6 flag",
                ))
            }
            _ => unimplemented!(),
        };
        // let ihl = byte0 & 0x0f;

        let byte1 = u8::read_from(bytestream, BigEndian)?;
        let dscp = byte1 >> 2;
        let enc = byte1 & 0x03;

        let len = u16::read_from(bytestream, BigEndian)?;
        if len < 20 {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "Ipv4 header requires the length field to be at least 20",
            ));
        }

        let identification = u16::read_from(bytestream, BigEndian)?;

        let fword = u16::read_from(bytestream, BigEndian)?;
        let flags = (fword >> 13) as u8;
        let fragment_offset = fword & 0x1fff;

        let ttl = u8::read_from(bytestream, BigEndian)?;
        let proto = u8::read_from(bytestream, BigEndian)?;

        let _checksum = u16::read_from(bytestream, BigEndian)?;
        // TODO: check checksum

        let src = Ipv4Addr::from(u32::read_from(bytestream, BigEndian)?);
        let dest = Ipv4Addr::from(u32::read_from(bytestream, BigEndian)?);

        Ok(Self {
            dscp,
            enc,
            len,
            identification,
            flags,
            fragment_offset,
            ttl,
            proto,
            src,
            dest,
        })
    }
}

impl MessageBody for Ipv4Header {
    fn byte_len(&self) -> usize {
        20
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use super::*;

    #[test]
    fn valid() -> Result<(), Box<dyn Error>> {
        let hd = Ipv4Header {
            dscp: 23,
            len: 82,
            enc: 0,
            identification: 123,
            flags: 0,
            fragment_offset: 332,
            ttl: 32,
            proto: 42,
            src: Ipv4Addr::new(1, 2, 3, 4),
            dest: Ipv4Addr::new(255, 255, 1, 3),
        };
        assert_eq!(hd, Ipv4Header::from_slice(&hd.to_vec()?)?);

        let hd = Ipv4Header {
            dscp: 0,
            len: 20,
            enc: 0,
            identification: 123,
            flags: 1,
            fragment_offset: 332,
            ttl: 31,
            proto: 42,
            src: Ipv4Addr::new(123, 2, 3, 4),
            dest: Ipv4Addr::new(255, 255, 1, 3),
        };
        assert_eq!(hd, Ipv4Header::from_slice(&hd.to_vec()?)?);

        let hd = Ipv4Header {
            dscp: 0,
            len: 82,
            enc: 2,
            identification: 123,
            flags: 3,
            fragment_offset: 0,
            ttl: 0,
            proto: 1,
            src: Ipv4Addr::new(1, 2, 3, 4),
            dest: Ipv4Addr::new(255, 255, 1, 3),
        };
        assert_eq!(hd, Ipv4Header::from_slice(&hd.to_vec()?)?);
        Ok(())
    }

    #[test]
    fn invalid_value_out_of_bounds() {
        let hd = Ipv4Header {
            dscp: u8::MAX,
            len: 82,
            enc: 1,
            identification: 123,
            flags: 2,
            fragment_offset: 0,
            ttl: 0,
            proto: 1,
            src: Ipv4Addr::new(1, 2, 3, 4),
            dest: Ipv4Addr::new(255, 255, 1, 3),
        };

        let err = hd.to_vec().unwrap_err();
        assert_eq!(format!("{err}"), "Ipv4 DSCP out of bounds (6 bit field)");

        let hd = Ipv4Header {
            dscp: 0,
            len: 82,
            enc: 22,
            identification: 123,
            flags: 0,
            fragment_offset: 0,
            ttl: 0,
            proto: 1,
            src: Ipv4Addr::new(1, 2, 3, 4),
            dest: Ipv4Addr::new(255, 255, 1, 3),
        };

        let err = hd.to_vec().unwrap_err();
        assert_eq!(format!("{err}"), "Ipv4 ENC out of bounds (2 bit field)");

        let hd = Ipv4Header {
            dscp: 0,
            len: 82,
            enc: 0,
            identification: 123,
            flags: 30,
            fragment_offset: u16::MAX,
            ttl: 0,
            proto: 1,
            src: Ipv4Addr::new(1, 2, 3, 4),
            dest: Ipv4Addr::new(255, 255, 1, 3),
        };

        let err = hd.to_vec().unwrap_err();
        assert_eq!(format!("{err}"), "Ipv4 flags out of bounds (2 bit field)");

        let hd = Ipv4Header {
            dscp: 0,
            len: 82,
            enc: 0,
            identification: 123,
            flags: 0,
            fragment_offset: u16::MAX,
            ttl: 0,
            proto: 1,
            src: Ipv4Addr::new(1, 2, 3, 4),
            dest: Ipv4Addr::new(255, 255, 1, 3),
        };

        let err = hd.to_vec().unwrap_err();
        assert_eq!(
            format!("{err}"),
            "Ipv4 fragment offset out of bounds (13 bit field)"
        );
    }

    #[test]
    fn invalid_ip_version() {
        let bytes = [0b0110_0000, 1, 2, 3, 4, 5];
        let ip = Ipv4Header::from_slice(&bytes);
        assert!(ip.is_err())
    }
}
