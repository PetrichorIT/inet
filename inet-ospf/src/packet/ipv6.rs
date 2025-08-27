use std::{io, net::Ipv6Addr};

use bitflags::bitflags;
use bytes_io::{BE, BytesReader, BytesWriter, FromBytes, ReadBytesExt, ToBytes, WriteBytesExt};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv6Prefix {
    pub prefix: Ipv6Addr,
    pub prefix_len: u8,
    pub prefix_options: Ipv6PrefixOptions,
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct Ipv6PrefixOptions: u8 {
        const NO_UNICAST    = 0b0000_0001;
        const LOCAL_ADDRESS = 0b0000_0010;
        const PROPAGATE     = 0b0000_1000;
        const DN            = 0b0001_0000;
    }
}

impl ToBytes for Ipv6Prefix {
    type Error = io::Error;
    fn to_bytes(&self, writer: &mut BytesWriter) -> Result<(), Self::Error> {
        writer.write_u8(self.prefix_len)?;
        writer.write_u8(self.prefix_options.bits())?;
        writer.write_u16::<BE>(0)?;

        // words
        let num_sgements = 2 * ((self.prefix_len as usize).div_ceil(32));
        let segments = &self.prefix.segments()[..num_sgements];
        for segment in segments {
            writer.write_u16::<BE>(*segment)?;
        }

        Ok(())
    }
}

impl FromBytes for Ipv6Prefix {
    type Error = io::Error;
    fn from_bytes(stream: &mut BytesReader) -> Result<Self, Self::Error> {
        let prefix_len = stream.read_u8()?;
        let prefix_options = Ipv6PrefixOptions::from_bits_truncate(stream.read_u8()?);
        let _reserved = stream.read_u16::<BE>()?;

        assert!(prefix_len <= 128);

        // words
        let num_segments = 2 * ((prefix_len as usize).div_ceil(32));
        let mut segments = [0u16; 8];
        for segment in &mut segments[..num_segments] {
            *segment = stream.read_u16::<BE>()?;
        }

        Ok(Ipv6Prefix {
            prefix_len,
            prefix_options,
            prefix: Ipv6Addr::from(segments),
        })
    }
}

#[cfg(test)]
mod tests {
    use bytes_io::assert_encoding_e2e;
    use rand::{Rng, rng};

    use super::*;

    impl Ipv6Prefix {
        pub fn random() -> Self {
            let prefix_len = rng().random_range(1..128);
            let mask = !(u128::MAX >> prefix_len);
            Ipv6Prefix {
                prefix: Ipv6Addr::from(rng().random::<u128>() & mask),
                prefix_len,
                prefix_options: Ipv6PrefixOptions::from_bits_truncate(rng().random()),
            }
        }
    }

    #[test]
    fn encoded_e2e() {
        let fuzzed = std::iter::repeat_with(Ipv6Prefix::random)
            .take(100)
            .collect::<Vec<_>>();
        assert_encoding_e2e(&fuzzed);
    }

    #[test]
    fn encode_64_bit_addr() {
        assert_eq!(
            Ipv6Prefix {
                prefix_len: 64,
                prefix_options: Ipv6PrefixOptions::empty(),
                prefix: Ipv6Addr::new(0x1234, 0x5678, 0x9abc, 0xdef0, 0, 0, 0, 0)
            }
            .write_to_vec()
            .expect("failed encode"),
            [
                64, 0, 0, 0, // len, options, reserved
                0x12, 0x34, 0x56, 0x78, //
                0x9a, 0xbc, 0xde, 0xf0, //
            ]
        );
    }

    #[test]
    fn encode_with_padding() {
        assert_eq!(
            Ipv6Prefix {
                prefix_len: 33,
                prefix_options: Ipv6PrefixOptions::empty(),
                prefix: Ipv6Addr::new(0x1234, 0x5678, 0x8000, 0x0000, 0, 0, 0, 0)
            }
            .write_to_vec()
            .expect("failed encode"),
            [
                33, 0, 0, 0, // len, options, reserved
                0x12, 0x34, 0x56, 0x78, //
                0x80, 0, 0, 0 //
            ]
        );

        assert_eq!(
            Ipv6Prefix {
                prefix_len: 56,
                prefix_options: Ipv6PrefixOptions::empty(),
                prefix: Ipv6Addr::new(0x1234, 0x5678, 0x9abc, 0xde00, 0, 0, 0, 0)
            }
            .write_to_vec()
            .expect("failed encode"),
            [
                56, 0, 0, 0, // len, options, reserved
                0x12, 0x34, 0x56, 0x78, //
                0x9a, 0xbc, 0xde, 0x00, //
            ]
        );
    }
}
