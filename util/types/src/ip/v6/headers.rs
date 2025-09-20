use bytes_io::{
    BE, Buf, Bytes, BytesReader, BytesWriter, FromBytes, ReadBytesExt, ToBytes, WriteBytesExt,
};
use macros::repr_enum;
use std::{
    io::{self, Write},
    net::Ipv6Addr,
};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Ipv6ExtensionHeader {
    HopByHopOptions(Ipv6HopToHopOptions),
    Routing(Ipv6RoutingHeader),
    Fragment(Ipv6FragmentHeader),
}

impl Ipv6ExtensionHeader {
    #[must_use]
    pub fn proto(&self) -> u8 {
        match self {
            Ipv6ExtensionHeader::HopByHopOptions(_) => NEXT_HEADER_HOP_TO_HOP_OPTIONS,
            Ipv6ExtensionHeader::Routing(_) => NEXT_HEADER_ROUTING,
            Ipv6ExtensionHeader::Fragment(_) => NEXT_HEADER_FRAGMENT,
        }
    }
}

impl ToBytes for Ipv6ExtensionHeader {
    type Error = io::Error;
    fn to_bytes(&self, writer: &mut BytesWriter) -> Result<(), Self::Error> {
        match self {
            Ipv6ExtensionHeader::HopByHopOptions(options) => options.to_bytes(writer),
            Ipv6ExtensionHeader::Routing(header) => header.to_bytes(writer),
            Ipv6ExtensionHeader::Fragment(header) => header.to_bytes(writer),
        }
    }
}

pub const NEXT_HEADER_HOP_TO_HOP_OPTIONS: u8 = 0;
pub const NEXT_HEADER_ROUTING: u8 = 43;
pub const NEXT_HEADER_FRAGMENT: u8 = 44;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct WithNextHeader<H>(pub H, pub u8);

impl<H> WithNextHeader<H> {
    pub fn map<T>(self, f: impl FnOnce(H) -> T) -> WithNextHeader<T> {
        WithNextHeader(f(self.0), self.1)
    }
}

impl<H: ToBytes<Error = io::Error>> ToBytes for WithNextHeader<H> {
    type Error = io::Error;
    fn to_bytes(&self, writer: &mut BytesWriter) -> Result<(), Self::Error> {
        writer.write_u8(self.1)?;
        let marker = writer.marker::<u8>();
        self.0.to_bytes(writer)?;
        let len = writer.bytes_written_since(&marker) - 6;
        writer.apply(marker).write_u8((len / 8) as u8)?;
        Ok(())
    }
}

impl<H: FromBytes<Error = io::Error>> FromBytes for WithNextHeader<H> {
    type Error = io::Error;
    fn from_bytes(stream: &mut BytesReader) -> Result<Self, Self::Error> {
        let next_header = stream.read_u8()?;
        let len = (stream.read_u8()? as usize * 8) + 6;
        let content = stream.extract(len, |body| H::from_bytes(body))?;
        Ok(WithNextHeader(content, next_header))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Ipv6HopToHopOptions {
    pub options: Vec<Ipv6Option>,
}

impl ToBytes for Ipv6HopToHopOptions {
    type Error = io::Error;
    fn to_bytes(&self, writer: &mut BytesWriter) -> Result<(), Self::Error> {
        let pos = writer.as_mut().len();
        for option in &self.options {
            option.to_bytes(writer)?;
        }
        let written = writer.as_mut().len() + 2; // equivalent to -2 for pos to get the start of the option writer
        let mut rem = (8 - (written - pos) % 8) % 8;
        while rem != 0 {
            match rem {
                1 => {
                    Ipv6Option::Pad1.to_bytes(writer)?;
                    rem -= 1;
                }
                n => {
                    Ipv6Option::PadN(n).to_bytes(writer)?;
                    rem -= n;
                }
            }
        }

        Ok(())
    }
}

impl FromBytes for Ipv6HopToHopOptions {
    type Error = io::Error;
    fn from_bytes(stream: &mut BytesReader) -> Result<Self, Self::Error> {
        let mut options = Vec::new();
        while stream.has_remaining() {
            let option = Ipv6Option::from_bytes(stream)?;
            if !option.is_padding() {
                options.push(option);
            }
        }
        Ok(Ipv6HopToHopOptions { options })
    }
}

const ROUTING_HEADER_TYPE_0: u8 = 0;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Ipv6RoutingHeader {
    Type0 {
        segments_left: u8,
        addresses: Vec<Ipv6Addr>,
    },
}

impl ToBytes for Ipv6RoutingHeader {
    type Error = io::Error;
    fn to_bytes(&self, writer: &mut BytesWriter) -> Result<(), Self::Error> {
        match self {
            Ipv6RoutingHeader::Type0 {
                segments_left,
                addresses,
            } => {
                writer.write_u8(ROUTING_HEADER_TYPE_0)?;
                writer.write_u8(*segments_left)?;
                writer.write_u32::<BE>(0)?;
                for addr in addresses {
                    writer.write_u128::<BE>(u128::from(*addr))?;
                }
            }
        }
        Ok(())
    }
}

impl FromBytes for Ipv6RoutingHeader {
    type Error = io::Error;
    fn from_bytes(stream: &mut BytesReader) -> Result<Self, Self::Error> {
        let rtype = stream.read_u8()?;
        match rtype {
            0 => {
                let segments_left = stream.read_u8()?;
                let _ = stream.read_u32::<BE>()?;
                let mut addresses = Vec::new();
                while stream.has_remaining() {
                    addresses.push(Ipv6Addr::from(stream.read_u128::<BE>()?));
                }
                Ok(Ipv6RoutingHeader::Type0 {
                    segments_left,
                    addresses,
                })
            }
            _ => Err(io::Error::new(io::ErrorKind::InvalidData, "invalid rtype")),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Ipv6FragmentHeader {
    fragment_offset: u16, // u13
    more_fragments: bool,
    identification: u32,
}

impl ToBytes for Ipv6FragmentHeader {
    type Error = io::Error;
    fn to_bytes(&self, writer: &mut BytesWriter) -> Result<(), Self::Error> {
        let word = ((self.fragment_offset & 0x1fff) << 3) | u16::from(self.more_fragments);
        writer.write_u16::<BE>(word)?;
        writer.write_u32::<BE>(self.identification)?;
        Ok(())
    }
}

impl FromBytes for Ipv6FragmentHeader {
    type Error = io::Error;
    fn from_bytes(stream: &mut BytesReader) -> Result<Self, Self::Error> {
        let word = stream.read_u16::<BE>()?;
        let fragment_offset = (word & 0xfff8) >> 3;
        let more_fragments = (word & 0x1) != 0;
        let identification = stream.read_u32::<BE>()?;
        Ok(Ipv6FragmentHeader {
            fragment_offset,
            more_fragments,
            identification,
        })
    }
}

const OPT_TYPE_PAD_1: u8 = 0x00;
const OPT_TYPE_PAD_N: u8 = 0x01;
const OPT_TYPE_JUMBO_PAYLOAD: u8 = 0xC2;
const OPT_TYPE_TUNNEL_ENCAPSULATION: u8 = 0x04;
const OPT_TYPE_ROUTER_ALERT: u8 = 0x05;
const OPT_TYPE_HOME_ADDR: u8 = 0xC9;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Ipv6Option {
    #[doc(hidden)]
    Pad1,
    #[doc(hidden)]
    PadN(usize),
    JumboPayload(u32),
    TunnelEncapsulation(u8),
    RouterAlert(Ipv6RouterAlertCode),
    HomeAddr(Ipv6Addr),
    Unknown(u8, Bytes),
}

impl Ipv6Option {
    pub fn is_padding(&self) -> bool {
        matches!(self, Ipv6Option::Pad1 | Ipv6Option::PadN(_))
    }
}

impl ToBytes for Ipv6Option {
    type Error = io::Error;
    fn to_bytes(&self, writer: &mut BytesWriter) -> Result<(), Self::Error> {
        match self {
            Ipv6Option::Pad1 => writer.write_u8(OPT_TYPE_PAD_1),
            Ipv6Option::PadN(n) => write_option(writer, OPT_TYPE_PAD_N, |body| {
                body.write_all(&vec![0; n - 2])
            }),
            Ipv6Option::JumboPayload(len) => write_option(writer, OPT_TYPE_JUMBO_PAYLOAD, |body| {
                body.write_u32::<BE>(*len)
            }),
            Ipv6Option::TunnelEncapsulation(limit) => {
                write_option(writer, OPT_TYPE_TUNNEL_ENCAPSULATION, |writer| {
                    writer.write_u8(*limit)?;
                    Ok(())
                })
            }
            Ipv6Option::RouterAlert(code) => write_option(writer, OPT_TYPE_ROUTER_ALERT, |body| {
                body.write_u16::<BE>(code.to_raw_repr())
            }),
            Ipv6Option::HomeAddr(addr) => write_option(writer, OPT_TYPE_HOME_ADDR, |body| {
                body.write_u128::<BE>(u128::from(*addr))
            }),
            Ipv6Option::Unknown(typ, data) => {
                write_option(writer, *typ, |writer| writer.write_all(data))
            }
        }
    }
}

fn write_option(
    writer: &mut BytesWriter,
    typ: u8,
    f: impl FnOnce(&mut BytesWriter) -> io::Result<()>,
) -> io::Result<()> {
    writer.write_u8(typ)?;
    let marker = writer.marker::<u8>();
    f(writer)?;
    let len = writer.bytes_written_since(&marker) as u8;
    writer.apply(marker).write_u8(len)?;
    Ok(())
}

impl FromBytes for Ipv6Option {
    type Error = io::Error;
    fn from_bytes(stream: &mut BytesReader) -> Result<Self, Self::Error> {
        let typ = stream.read_u8()?;
        if typ == OPT_TYPE_PAD_1 {
            return Ok(Ipv6Option::Pad1);
        }
        let len = stream.read_u8()?;
        let data = stream.copy_to_bytes(len as usize);
        Ipv6Option::from_unknown(typ, data)
    }
}

impl Ipv6Option {
    /// Create an unknown option from a type and data.
    ///
    /// # Errors
    ///
    /// Fails on missformed packets
    pub fn from_unknown(typ: u8, mut data: Bytes) -> io::Result<Self> {
        match typ {
            OPT_TYPE_PAD_N => Ok(Self::PadN(data.len() + 2)),
            OPT_TYPE_JUMBO_PAYLOAD => {
                let len = data.try_get_u32()?;
                if data.has_remaining() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Jumbo payload option has extra data",
                    ));
                }
                Ok(Self::JumboPayload(len))
            }
            OPT_TYPE_TUNNEL_ENCAPSULATION => {
                let limit = data.try_get_u8()?;
                if data.has_remaining() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Tunnel encapsulation option has extra data",
                    ));
                }
                Ok(Self::TunnelEncapsulation(limit))
            }
            OPT_TYPE_ROUTER_ALERT => {
                let code = Ipv6RouterAlertCode::from_raw_repr(data.try_get_u16()?)?;
                if data.has_remaining() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Router alert option has extra data",
                    ));
                }
                Ok(Self::RouterAlert(code))
            }
            OPT_TYPE_HOME_ADDR => {
                let addr = Ipv6Addr::from(data.try_get_u128()?);
                if data.has_remaining() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Home address option has extra data",
                    ));
                }
                Ok(Self::HomeAddr(addr))
            }

            _ => Ok(Self::Unknown(typ, data)),
        }
    }
}

repr_enum! {
    #[derive(Debug, Clone, PartialEq, Eq, Hash)]
    pub enum Ipv6RouterAlertCode {
        type Repr = u16 where BE;

        DatagramContainsMLD = 0,
        DatagramContainsRSVP = 1,
        DatagramContainsActiveNetworks = 2,
    }
}

#[cfg(test)]
mod tests {
    use bytes_io::assert_encoding_e2e;
    use rand::{Rng, rng, seq::IndexedRandom};

    use super::*;

    impl Ipv6ExtensionHeader {
        pub fn random() -> Self {
            match *[
                NEXT_HEADER_HOP_TO_HOP_OPTIONS,
                NEXT_HEADER_ROUTING,
                NEXT_HEADER_FRAGMENT,
            ]
            .choose(&mut rng())
            .unwrap()
            {
                NEXT_HEADER_HOP_TO_HOP_OPTIONS => {
                    Ipv6ExtensionHeader::HopByHopOptions(Ipv6HopToHopOptions::random())
                }
                NEXT_HEADER_ROUTING => Ipv6ExtensionHeader::Routing(Ipv6RoutingHeader::random()),
                NEXT_HEADER_FRAGMENT => Ipv6ExtensionHeader::Fragment(Ipv6FragmentHeader::random()),
                _ => unreachable!(),
            }
        }
    }

    impl Ipv6HopToHopOptions {
        pub fn random() -> Self {
            Self {
                options: std::iter::repeat_with(Ipv6Option::random)
                    .take((rng().random::<u8>() % 3) as usize + 1)
                    .collect(),
            }
        }
    }

    #[test]
    fn e2e_hop2hop_options() {
        let fuzzed = std::iter::repeat_with(Ipv6HopToHopOptions::random)
            .take(100)
            .collect::<Vec<_>>();
        assert_encoding_e2e(&fuzzed);
    }

    impl Ipv6RoutingHeader {
        pub fn random() -> Self {
            Self::Type0 {
                segments_left: rng().random(),
                addresses: std::iter::repeat_with(|| Ipv6Addr::from(rng().random::<u128>()))
                    .take((rng().random::<u8>() % 6) as usize + 1)
                    .collect(),
            }
        }
    }

    #[test]
    fn e2e_routing_header() {
        let fuzzed = std::iter::repeat_with(Ipv6RoutingHeader::random)
            .take(100)
            .collect::<Vec<_>>();
        assert_encoding_e2e(&fuzzed);
    }

    impl Ipv6FragmentHeader {
        pub fn random() -> Self {
            Self {
                fragment_offset: rng().random_range(0..0x1fff),
                more_fragments: rng().random(),
                identification: rng().random(),
            }
        }
    }

    #[test]
    fn e2e_fragment_header() {
        let fuzzed = std::iter::repeat_with(Ipv6FragmentHeader::random)
            .take(100)
            .collect::<Vec<_>>();
        assert_encoding_e2e(&fuzzed);
    }

    impl Ipv6Option {
        pub fn random() -> Self {
            match *[
                OPT_TYPE_TUNNEL_ENCAPSULATION,
                OPT_TYPE_JUMBO_PAYLOAD,
                OPT_TYPE_ROUTER_ALERT,
                OPT_TYPE_HOME_ADDR,
            ]
            .choose(&mut rng())
            .unwrap()
            {
                OPT_TYPE_TUNNEL_ENCAPSULATION => Self::TunnelEncapsulation(rng().random()),
                OPT_TYPE_JUMBO_PAYLOAD => Self::JumboPayload(rng().random_range(1..=u32::MAX)),
                OPT_TYPE_ROUTER_ALERT => Self::RouterAlert(
                    Ipv6RouterAlertCode::from_raw_repr(rng().random::<u16>() % 3).unwrap(),
                ),
                OPT_TYPE_HOME_ADDR => Self::HomeAddr(Ipv6Addr::from(rng().random::<u128>())),
                _ => unreachable!(),
            }
        }
    }

    #[test]
    fn e2e_encoding_options() {
        let fuzzed = std::iter::repeat_with(Ipv6Option::random)
            .take(100)
            .collect::<Vec<_>>();
        assert_encoding_e2e(&fuzzed);
    }
}
