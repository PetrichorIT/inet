use std::{
    io::{Error, Write},
    net::Ipv4Addr,
};

use bytes_io::{BE, BytesReader, BytesWriter, FromBytes, ReadBytesExt, ToBytes, WriteBytesExt};
use macros::repr_enum;

use crate::types::AsNumber;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BgpPathAttribute {
    pub flags: BgpPathAttributeFlags,
    // pub len: u16, // or u8,
    pub attr: BgpPathAttributeKind,
}

impl ToBytes for BgpPathAttribute {
    type Error = Error;
    fn to_bytes(&self, stream: &mut BytesWriter) -> Result<(), Self::Error> {
        self.flags.to_bytes(stream)?;
        stream.write_u8(self.attr.kind())?;

        let len = self.attr.len();
        if self.flags.extended_len {
            stream.write_u16::<BE>(len as u16)?;
        } else {
            stream.write_u8(len as u8)?;
        }

        self.attr.to_bytes(stream)?;
        Ok(())
    }
}

impl FromBytes for BgpPathAttribute {
    type Error = Error;
    fn from_bytes(stream: &mut BytesReader) -> Result<Self, Self::Error> {
        let flags = BgpPathAttributeFlags::from_bytes(stream)?;
        let kind = stream.read_u8()?;
        let len = if flags.extended_len {
            stream.read_u16::<BE>()? as usize
        } else {
            stream.read_u8()? as usize
        };
        let attr = stream.extract(len, |substream| match kind {
            1 => Ok(BgpPathAttributeKind::Origin(
                BgpPathAttributeOrigin::from_raw_repr(substream.read_u8()?)?,
            )),
            2 if len > 0 => Ok(BgpPathAttributeKind::AsPath(
                BgpPathAttributeAsPath::from_bytes(substream)?,
            )),
            2 if len == 0 => Ok(BgpPathAttributeKind::AsPath(BgpPathAttributeAsPath {
                typ: BgpPathAttributeAsPathTyp::AsSequence,
                path: Vec::new(),
            })),
            3 => Ok(BgpPathAttributeKind::NextHop(
                BgpPathAttributeNextHop::from_bytes(substream)?,
            )),
            _ => todo!(),
        })?;

        Ok(BgpPathAttribute { flags, attr })
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)]
pub struct BgpPathAttributeFlags {
    pub optional: bool, // MSB
    pub transitiv: bool,
    pub partial: bool,
    pub extended_len: bool,
    /* 4 LSB unused */
}

impl ToBytes for BgpPathAttributeFlags {
    type Error = Error;
    fn to_bytes(&self, bytestream: &mut BytesWriter) -> Result<(), Self::Error> {
        let mut byte = 0u8;
        if self.optional {
            byte |= 0b1000_0000;
        }
        if self.transitiv {
            byte |= 0b0100_0000;
        }
        if self.partial {
            byte |= 0b0010_0000;
        }
        if self.extended_len {
            byte |= 0b0001_0000;
        }
        bytestream.write_u8(byte)?;
        Ok(())
    }
}

impl FromBytes for BgpPathAttributeFlags {
    type Error = Error;
    fn from_bytes(bytestream: &mut BytesReader) -> Result<Self, Self::Error> {
        let byte = bytestream.read_u8()?;
        Ok(Self {
            optional: byte & 0b1000_0000 != 0,
            transitiv: byte & 0b0100_0000 != 0,
            partial: byte & 0b0010_0000 != 0,
            extended_len: byte & 0b0001_0000 != 0,
        })
    }
}

// real 40010101
// sim  40010101

#[derive(Debug, Clone, PartialEq, Eq)]
#[repr(u8)]
pub enum BgpPathAttributeKind {
    Origin(BgpPathAttributeOrigin) = 1,
    AsPath(BgpPathAttributeAsPath) = 2,
    NextHop(BgpPathAttributeNextHop) = 3,
    /* and more */
}

impl BgpPathAttributeKind {
    fn kind(&self) -> u8 {
        match self {
            Self::Origin(_) => 1,
            Self::AsPath(_) => 2,
            Self::NextHop(_) => 3,
        }
    }

    fn len(&self) -> usize {
        match self {
            Self::Origin(_) => 1,
            Self::AsPath(path) => {
                if path.path.is_empty() {
                    0
                } else {
                    path.path.len() * 4 + 2
                }
            }
            Self::NextHop(_) => 4,
        }
    }
}

impl ToBytes for BgpPathAttributeKind {
    type Error = Error;
    fn to_bytes(&self, bytestream: &mut BytesWriter) -> Result<(), Self::Error> {
        match self {
            Self::Origin(origin) => bytestream.write_u8(origin.to_raw_repr()),
            Self::AsPath(path) => path.to_bytes(bytestream),
            Self::NextHop(next_hop) => next_hop.to_bytes(bytestream),
        }
    }
}

repr_enum! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum BgpPathAttributeOrigin {
        type Repr = u8 where ByteOrder::BigEndian;
        Igp = 0,
        Egp = 1,
        Incomplete = 2,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BgpPathAttributeAsPath {
    pub typ: BgpPathAttributeAsPathTyp,
    // pub len: u8,
    pub path: Vec<AsNumber>,
}

impl ToBytes for BgpPathAttributeAsPath {
    type Error = Error;
    fn to_bytes(&self, bytestream: &mut BytesWriter) -> Result<(), Self::Error> {
        if !self.path.is_empty() {
            bytestream.write_u8(self.typ.to_raw_repr())?;
            bytestream.write_u8(self.path.len() as u8)?;
            for seg in &self.path {
                bytestream.write_u32::<BE>(u32::from(*seg))?;
            }
        }
        Ok(())
    }
}

impl FromBytes for BgpPathAttributeAsPath {
    type Error = Error;
    fn from_bytes(bytestream: &mut BytesReader) -> Result<Self, Self::Error> {
        let typ = bytestream.read_u8()?;
        let typ = match typ {
            1 => BgpPathAttributeAsPathTyp::AsSet,
            2 => BgpPathAttributeAsPathTyp::AsSequence,
            _ => todo!(),
        };
        let len = bytestream.read_u8()?;
        let mut path = Vec::new();
        for _i in 0..len {
            // dbg!(as_num);02 02 00 00 fe 4c 00 00 fe b0
            let as_num = bytestream.read_u32::<BE>()?;
            path.push(as_num as u16);
        }
        Ok(Self { typ, path })
    }
}

repr_enum! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum BgpPathAttributeAsPathTyp {
        type Repr = u8 where ByteOrder::BigEndian;

        AsSet = 1,
        AsSequence = 2,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BgpPathAttributeNextHop {
    pub hop: Ipv4Addr,
}

impl ToBytes for BgpPathAttributeNextHop {
    type Error = Error;
    fn to_bytes(&self, bytestream: &mut BytesWriter) -> Result<(), Self::Error> {
        bytestream.write_all(&self.hop.octets())
    }
}

impl FromBytes for BgpPathAttributeNextHop {
    type Error = Error;
    fn from_bytes(bytestream: &mut BytesReader) -> Result<Self, Self::Error> {
        Ok(BgpPathAttributeNextHop {
            hop: Ipv4Addr::from(bytestream.read_u32::<BE>()?),
        })
    }
}

#[cfg(test)]
mod tests {
    use bytes_io::assert_encoding_e2e;

    use super::*;

    #[test]
    fn e2e_encoding_path_attr() {
        assert_encoding_e2e(&[
            BgpPathAttribute {
                flags: BgpPathAttributeFlags::default(),
                attr: BgpPathAttributeKind::Origin(BgpPathAttributeOrigin::Egp),
            },
            BgpPathAttribute {
                flags: BgpPathAttributeFlags::default(),
                attr: BgpPathAttributeKind::Origin(BgpPathAttributeOrigin::Igp),
            },
            BgpPathAttribute {
                flags: BgpPathAttributeFlags::default(),
                attr: BgpPathAttributeKind::Origin(BgpPathAttributeOrigin::Incomplete),
            },
            //
            BgpPathAttribute {
                flags: BgpPathAttributeFlags::default(),
                attr: BgpPathAttributeKind::AsPath(BgpPathAttributeAsPath {
                    typ: BgpPathAttributeAsPathTyp::AsSequence,
                    path: vec![13123, 3123, 123],
                }),
            },
            //
            BgpPathAttribute {
                flags: BgpPathAttributeFlags::default(),
                attr: BgpPathAttributeKind::NextHop(BgpPathAttributeNextHop {
                    hop: Ipv4Addr::new(123, 3, 31, 4),
                }),
            },
            BgpPathAttribute {
                flags: BgpPathAttributeFlags::default(),
                attr: BgpPathAttributeKind::NextHop(BgpPathAttributeNextHop {
                    hop: Ipv4Addr::new(3, 13, 231, 4),
                }),
            },
        ]);
    }

    #[test]
    fn e2e_encoding_path_attr_flags() {
        assert_encoding_e2e(&[
            BgpPathAttributeFlags {
                optional: true,
                transitiv: false,
                partial: false,
                extended_len: true,
            },
            BgpPathAttributeFlags {
                optional: false,
                transitiv: true,
                partial: false,
                extended_len: true,
            },
        ]);
    }

    #[test]
    fn e2e_encoding_path_attr_as_path() {
        assert_encoding_e2e(&[
            BgpPathAttributeAsPath {
                typ: BgpPathAttributeAsPathTyp::AsSequence,
                path: vec![1, 2, 3],
            },
            BgpPathAttributeAsPath {
                typ: BgpPathAttributeAsPathTyp::AsSet,
                path: vec![1, 4440, 1414, 4],
            },
            BgpPathAttributeAsPath {
                typ: BgpPathAttributeAsPathTyp::AsSet,
                path: vec![4],
            },
        ]);
    }
}
