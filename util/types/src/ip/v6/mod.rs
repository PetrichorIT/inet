use bytes_io::{
    BufMut, Bytes, BytesReader, BytesWriter, FromBytes, ReadBytesExt, ToBytes, WriteBytesExt, BE,
};
use des::net::message::MessageBody;
use std::{
    io::{Error, ErrorKind, Write},
    iter::once,
    net::Ipv6Addr,
};

mod addr;
mod headers;

pub use addr::*;
pub use headers::*;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Ipv6Packet {
    pub traffic_class: u8,
    pub flow_label: u32, // u20
    /// A protocol identifier for the contained upper layer payload. This is not nessecarily the value
    /// of the `next_header` IPv6 field, if extension headers are present.
    pub proto: u8,
    pub hop_limit: u8,

    pub extension_headers: Vec<Ipv6ExtensionHeader>,

    pub src: Ipv6Addr,
    pub dst: Ipv6Addr,
    pub content: Bytes,
}

impl ToBytes for Ipv6Packet {
    type Error = std::io::Error;
    fn to_bytes(&self, stream: &mut BytesWriter) -> Result<(), Self::Error> {
        let header = (6 << 4) | (self.traffic_class >> 4);
        stream.write_u8(header)?;

        let bytes = self.flow_label.to_be_bytes();
        let byte_0 = ((self.traffic_class & 0b1111) << 4) | bytes[1] & 0b1111;
        stream.write_u8(byte_0)?;
        stream.write_u8(bytes[2])?;
        stream.write_u8(bytes[3])?;

        let len_marker = stream.marker::<u16>();
        stream.write_u8(
            self.extension_headers
                .first()
                .map(|v| v.proto())
                .unwrap_or(self.proto),
        )?;
        stream.write_u8(self.hop_limit)?;

        stream.write_u128::<BE>(u128::from(self.src))?;
        stream.write_u128::<BE>(u128::from(self.dst))?;

        if !self.extension_headers.is_empty() {
            let next_headers = self
                .extension_headers
                .iter()
                .skip(1)
                .map(|v| v.proto())
                .chain(once(self.proto));

            for (ext, next) in self.extension_headers.iter().zip(next_headers) {
                WithNextHeader(ext, next).to_bytes(stream)?;
            }
        }

        stream.write_all(&self.content)?;

        let total_len = stream.bytes_written_since(&len_marker) - 34;
        stream.apply(len_marker).put_u16(total_len as u16);
        Ok(())
    }
}

impl FromBytes for Ipv6Packet {
    type Error = std::io::Error;
    fn from_bytes(stream: &mut BytesReader) -> Result<Self, Self::Error> {
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

        let mut len = stream.read_u16::<BE>()?;
        let mut next_header = stream.read_u8()?;
        let hop_limit = stream.read_u8()?;

        let src = Ipv6Addr::from(stream.read_u128::<BE>()?);
        let dst = Ipv6Addr::from(stream.read_u128::<BE>()?);

        let mut extension_headers = Vec::new();
        loop {
            let pre_img = stream.remaining();
            let WithNextHeader(hdr, next) = match next_header {
                NEXT_HEADER_HOP_TO_HOP_OPTIONS => {
                    WithNextHeader::<Ipv6HopToHopOptions>::from_bytes(stream)?
                        .map(|opt| Ipv6ExtensionHeader::HopByHopOptions(opt))
                }
                NEXT_HEADER_ROUTING => WithNextHeader::<Ipv6RoutingHeader>::from_bytes(stream)?
                    .map(|opt| Ipv6ExtensionHeader::Routing(opt)),
                NEXT_HEADER_FRAGMENT => WithNextHeader::<Ipv6FragmentHeader>::from_bytes(stream)?
                    .map(|opt| Ipv6ExtensionHeader::Fragment(opt)),
                _ => break,
            };
            let n = pre_img - stream.remaining();

            len -= n as u16;
            next_header = next;
            extension_headers.push(hdr);
        }

        // fetch rest, according to len
        let content = stream.copy_to_bytes(len as usize);

        Ok(Self {
            traffic_class,
            flow_label,
            proto: next_header,
            hop_limit,
            extension_headers,
            src,
            dst,
            content,
        })
    }
}

impl MessageBody for Ipv6Packet {
    fn byte_len(&self) -> usize {
        40 + self.content.len()
    }
}

#[cfg(test)]
mod tests {
    use bytes_io::assert_encoding_e2e;
    use rand::{rng, seq::IndexedRandom, Rng};

    use super::*;

    // #[test]
    // fn len_comp() {
    //     let hdr = Ipv6Packet {
    //         traffic_class: rng().random::<u8>(),
    //         flow_label: rng().random::<u32>() & 0b1111_1111_1111_1111_1111,
    //         proto: rng().random::<u8>(),
    //         hop_limit: rng().random::<u8>(),
    //         extension_headers: Vec::new(),
    //         src: Ipv6Addr::from(rng().random::<u128>()),
    //         dst: Ipv6Addr::from(rng().random::<u128>()),
    //         content: Bytes::from_static(b"Hello wolrd!"),
    //     };

    //     panic!("{}", (&hdr.write_to_bytes().unwrap()[4..6]).get_u16());
    // }

    #[test]
    fn e2e_encoding_fuzz() {
        let fuzzed = std::iter::repeat_with(|| Ipv6Packet {
            traffic_class: rng().random::<u8>(),
            flow_label: rng().random::<u32>() & 0b1111_1111_1111_1111_1111,
            proto: rng().random_range(50..255),
            hop_limit: rng().random::<u8>(),
            extension_headers: std::iter::repeat_with(Ipv6ExtensionHeader::random)
                .take(*[0, 0, 0, 0, 1, 2, 3, 4, 5, 6].choose(&mut rng()).unwrap())
                .collect(),
            src: Ipv6Addr::from(rng().random::<u128>()),
            dst: Ipv6Addr::from(rng().random::<u128>()),
            content: std::iter::repeat_with(|| rng().random())
                .take((rng().random::<u32>() % 100) as usize)
                .collect(),
        })
        .take(100)
        .collect::<Vec<_>>();

        assert_encoding_e2e(&fuzzed);
    }
}
