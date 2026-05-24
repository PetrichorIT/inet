use bytes_io::{
    BE, BufMut, Bytes, BytesMut, BytesReader, BytesWriter, FromBytes, ReadBytesExt, ToBytes,
    WriteBytesExt,
};
use des::message::MessageBody;
use std::{
    io::{self, Error, ErrorKind, Write},
    iter::once,
    net::Ipv6Addr,
};

mod addr;
mod headers;

pub use addr::*;
pub use headers::*;

pub const IPV6_MINIMUM_MTU: usize = 1280;

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

impl Ipv6Packet {
    pub const MIN_HEADER_SIZE: usize = 40;

    /// Assume all same identification
    ///
    /// # Errors
    ///
    /// Returns an error if the fragments do not form a valid packet.
    #[allow(clippy::missing_panics_doc)]
    pub fn from_fragments(fragments: &mut [Ipv6Packet]) -> io::Result<Ipv6Packet> {
        fragments.sort_by_key(|pkt| pkt.if_fragment_header(|h| h.fragment_offset).unwrap_or(0));

        let mut pkt = fragments[0].clone();

        // (1) Check first packet requirements
        let (frag_index, header) = pkt
            .extension_headers
            .iter()
            .enumerate()
            .find_map(|(i, h)| match h {
                Ipv6ExtensionHeader::Fragment(farg) => Some((i, farg)),
                _ => None,
            })
            .expect("packets without fragmentation headers should not be passed to this function");
        let header = header.clone();
        if header.fragment_offset != 0 {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "initial fragment header had non zero offset",
            ));
        }
        pkt.extension_headers.remove(frag_index);

        let mut slices = vec![pkt.content.clone()];
        let mut offset = pkt.content.len();
        let mut finalized = false;

        for additional in &fragments[1..] {
            // (2.1) Header identical
            let meta_valid = additional.flow_label == pkt.flow_label
                && additional.traffic_class == pkt.traffic_class
                && additional.proto == pkt.proto;
            let addr_valid = additional.src == pkt.src && additional.dst == pkt.dst;
            let valid = meta_valid && addr_valid;
            if !valid {
                return Err(Error::new(ErrorKind::InvalidData, "unrelated packets"));
            }

            // (2.1) Fragment extension is correct
            let header = additional
                .extension_headers
                .iter()
                .find_map(|h| match h {
                    Ipv6ExtensionHeader::Fragment(farg) => Some(farg),
                    _ => None,
                })
                .expect(
                    "packets without fragmentation headers should not be passed to this function",
                );

            if header.fragment_offset as usize != offset / 8 {
                return Err(Error::new(ErrorKind::InvalidData, "invalid offset point"));
            }

            // (2.3) Add fragment
            slices.push(additional.content.clone());
            offset += additional.content.len();

            if !header.more_fragments {
                finalized = true;
                break;
            }
        }

        if !finalized {
            return Err(Error::new(ErrorKind::InvalidData, "not yet final"));
        }

        let mut buf = BytesMut::with_capacity(offset);
        for slice in slices {
            buf.extend_from_slice(&slice[..]);
        }

        pkt.content = buf.freeze();

        // When reassembling node detects a fragment that overlaps with another fragment, the reassembly of the original packet
        // is aborted and all fragments are dropped. A node may optionally ignore the exact duplicates of a fragment instead
        // of treating exact duplicates as overlapping each other.

        Ok(pkt)
    }

    fn if_fragment_header<R>(&self, mut f: impl FnMut(&Ipv6FragmentHeader) -> R) -> Option<R> {
        self.extension_headers
            .iter()
            .find_map(|header| match header {
                Ipv6ExtensionHeader::Fragment(frag) => Some(f(frag)),
                _ => None,
            })
    }

    /// Fragments the packet into fragments that fit within the given MTU.
    ///
    /// # Panics
    ///
    /// Panics if the MTU is less than the minimum IPv6 MTU (1280 bytes).
    pub fn fragment_to_mtu(&self, mtu: usize, identification: u32) -> Vec<Ipv6Packet> {
        assert!(mtu >= IPV6_MINIMUM_MTU);
        let mtu = mtu - (mtu % 8); // < enforces that all encoding belong to a 8 octet boundary

        let mut fragments = Vec::new();
        let mut content = self.content.clone();
        let mut offset_in_bytes = 0;

        // The per-fragment headers are determined based on whether the original contains Routing or Hop-by-Hop extension header.
        // a) If neither exists, the per-fragment part is just the fixed header.
        // b) If the Routing extension header exists, the per-fragment headers include the fixed header and all the extension headers up to and including the Routing one.
        // c) If the Hop-by-Hop extension header exists, the per-fragment headers consist of only the fixed header and the Hop-by-Hop extension header.

        let (per_fragment_extension_headers, mut other_extension_headers) = {
            let r_header = self
                .extension_headers
                .iter()
                .position(|h| matches!(h, Ipv6ExtensionHeader::Routing(_)));
            let hbh_header = self
                .extension_headers
                .iter()
                .position(|h| matches!(h, Ipv6ExtensionHeader::HopByHopOptions(_)));
            match (r_header, hbh_header) {
                (Some(i), None) => (
                    self.extension_headers[..=i].to_vec(),
                    self.extension_headers[(i + 1)..].to_vec(),
                ),
                (None, Some(i)) => (vec![self.extension_headers[i].clone()], {
                    let mut buf = self.extension_headers.clone();
                    buf.remove(i);
                    buf
                }),
                _ => (Vec::new(), self.extension_headers.clone()), // FIXME: is that even allowed
            }
        };

        let per_fragment_header = Ipv6Packet {
            traffic_class: self.traffic_class,
            flow_label: self.flow_label,
            proto: self.proto,
            hop_limit: self.hop_limit,
            src: self.src,
            dst: self.dst,
            extension_headers: per_fragment_extension_headers,
            content: Bytes::new(),
        };

        // A packet holding the first part of an original overlarge packet contains 5 parts:
        // 1) pre-fragment header
        // 2) fragment-extension header with offset 0
        // 3) original extension headers
        // 4) upper layer header
        // 5) first part of the original payload

        let mut first = per_fragment_header.clone();
        first
            .extension_headers
            .push(Ipv6ExtensionHeader::Fragment(Ipv6FragmentHeader {
                fragment_offset: 0,
                more_fragments: true,
                identification,
            }));
        first.extension_headers.append(&mut other_extension_headers);

        let mut extension_header_len = 0;
        for header in &first.extension_headers {
            extension_header_len += 2 + header.write_to_bytes().expect("failed to encode").len();
        }
        assert_eq!(extension_header_len % 8, 0);
        let eff_header_size = Self::MIN_HEADER_SIZE + extension_header_len;
        let s1 = (mtu - eff_header_size).min(self.content.len()); // either dividable by 8 or content-len

        first.content = content.split_to(s1);

        fragments.push(first);
        offset_in_bytes += s1;

        assert!(!self.content.is_empty(), "no fragmentation needed");

        // Each subsequenct packet contains the following
        // 1) pre-fragment header
        // 2) fragment-extension header with offset > 0
        // 3) payload part

        while !content.is_empty() {
            let s2 = (mtu - eff_header_size - 8).min(content.len()); // either dividable by 8 or content-len
            let mut fragment = per_fragment_header.clone();
            fragment
                .extension_headers
                .push(Ipv6ExtensionHeader::Fragment(Ipv6FragmentHeader {
                    more_fragments: s2 < content.len(),
                    identification,
                    fragment_offset: (offset_in_bytes / 8) as u16,
                }));
            fragment.content = content.split_to(s2);

            fragments.push(fragment);
            offset_in_bytes += s2;
        }

        fragments
    }
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
                .map_or(self.proto, Ipv6ExtensionHeader::proto),
        )?;
        stream.write_u8(self.hop_limit)?;

        stream.write_u128::<BE>(u128::from(self.src))?;
        stream.write_u128::<BE>(u128::from(self.dst))?;

        if !self.extension_headers.is_empty() {
            let next_headers = self
                .extension_headers
                .iter()
                .skip(1)
                .map(Ipv6ExtensionHeader::proto)
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
                        .map(Ipv6ExtensionHeader::HopByHopOptions)
                }
                NEXT_HEADER_ROUTING => WithNextHeader::<Ipv6RoutingHeader>::from_bytes(stream)?
                    .map(Ipv6ExtensionHeader::Routing),
                NEXT_HEADER_FRAGMENT => WithNextHeader::<Ipv6FragmentHeader>::from_bytes(stream)?
                    .map(Ipv6ExtensionHeader::Fragment),
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
    use rand::{Rng, rng, seq::IndexedRandom};

    use super::*;

    impl Ipv6Packet {
        pub(crate) fn random(content: Bytes) -> Self {
            Ipv6Packet {
                traffic_class: rng().random::<u8>(),
                flow_label: rng().random::<u32>() & 0b1111_1111_1111_1111_1111,
                proto: rng().random_range(50..255),
                hop_limit: rng().random::<u8>(),
                extension_headers: std::iter::repeat_with(Ipv6ExtensionHeader::random)
                    .take(*[0, 0, 0, 0, 1, 2, 3, 4, 5, 6].choose(&mut rng()).unwrap())
                    .collect(),
                src: Ipv6Addr::from(rng().random::<u128>()),
                dst: Ipv6Addr::from(rng().random::<u128>()),
                content,
            }
        }
    }

    #[test]
    fn e2e_encoding_fuzz() {
        let fuzzed = std::iter::repeat_with(|| {
            Ipv6Packet::random(
                std::iter::repeat_with(|| rng().random())
                    .take((rng().random::<u32>() % 100) as usize)
                    .collect(),
            )
        })
        .take(100)
        .collect::<Vec<_>>();

        assert_encoding_e2e(&fuzzed);
    }

    #[test]
    fn fragment_generation() -> io::Result<()> {
        let fuzzed = std::iter::repeat_with(|| {
            let mut pkt = Ipv6Packet::random(
                std::iter::repeat_with(|| rng().random())
                    .take((1600 + rng().random::<u64>() % 60_000) as usize)
                    .collect(),
            );
            pkt.extension_headers
                .retain(|v| !matches!(v, Ipv6ExtensionHeader::Fragment(_)));
            pkt
        })
        .take(100)
        .collect::<Vec<_>>();

        for pkt in fuzzed {
            let mut fragmented = pkt.fragment_to_mtu(1500, rng().random());
            for (i, frag) in fragmented.iter().enumerate() {
                let encoded = frag.write_to_bytes()?;
                assert!(
                    encoded.len() <= 1500,
                    "invalid packet with {} bytes on index {}",
                    encoded.len(),
                    i
                );
            }

            let reassembled = Ipv6Packet::from_fragments(&mut fragmented)?;
            assert_eq!(pkt, reassembled);
        }
        Ok(())
    }
}
