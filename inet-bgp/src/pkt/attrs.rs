use std::{
    io::{Error, Write},
    net::Ipv4Addr,
};

use bytepack::{
    raw_enum, BytestreamReader, BytestreamWriter, FromBytestream, ReadBytesExt, ToBytestream,
    WriteBytesExt, BE,
};

use crate::types::AsNumber;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BgpPathAttribute {
    pub flags: BgpPathAttributeFlags,
    // pub len: u16, // or u8,
    pub attr: BgpPathAttributeKind,
}

impl ToBytestream for BgpPathAttribute {
    type Error = Error;
    fn to_bytestream(&self, stream: &mut BytestreamWriter) -> Result<(), Self::Error> {
        self.flags.to_bytestream(stream)?;
        stream.write_u8(self.attr.kind())?;

        let len = self.attr.len();
        if self.flags.extended_len {
            stream.write_u16::<BE>(len as u16)?;
        } else {
            stream.write_u8(len as u8)?;
        }

        self.attr.to_bytestream(stream)?;
        Ok(())
    }
}

impl FromBytestream for BgpPathAttribute {
    type Error = Error;
    fn from_bytestream(stream: &mut BytestreamReader) -> Result<Self, Self::Error> {
        let flags = BgpPathAttributeFlags::from_bytestream(stream)?;
        let kind = stream.read_u8()?;
        let len = if flags.extended_len {
            stream.read_u16::<BE>()? as usize
        } else {
            stream.read_u8()? as usize
        };
        let mut substream = stream.extract(len)?;

        let attr = match kind {
            1 => BgpPathAttributeKind::Origin(BgpPathAttributeOrigin::from_raw_repr(
                substream.read_u8()?,
            )?),
            2 if len > 0 => BgpPathAttributeKind::AsPath(BgpPathAttributeAsPath::from_bytestream(
                &mut substream,
            )?),
            2 if len == 0 => BgpPathAttributeKind::AsPath(BgpPathAttributeAsPath {
                typ: BgpPathAttributeAsPathTyp::AsSequence,
                path: Vec::new(),
            }),
            3 => BgpPathAttributeKind::NextHop(BgpPathAttributeNextHop::from_bytestream(
                &mut substream,
            )?),
            _ => todo!(),
        };

        Ok(BgpPathAttribute { flags, attr })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BgpPathAttributeFlags {
    pub optional: bool, // MSB
    pub transitiv: bool,
    pub partial: bool,
    pub extended_len: bool,
    /* 4 LSB unused */
}

impl ToBytestream for BgpPathAttributeFlags {
    type Error = Error;
    fn to_bytestream(&self, bytestream: &mut BytestreamWriter) -> Result<(), Self::Error> {
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

impl FromBytestream for BgpPathAttributeFlags {
    type Error = Error;
    fn from_bytestream(bytestream: &mut BytestreamReader) -> Result<Self, Self::Error> {
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

impl ToBytestream for BgpPathAttributeKind {
    type Error = Error;
    fn to_bytestream(&self, bytestream: &mut BytestreamWriter) -> Result<(), Self::Error> {
        match self {
            Self::Origin(origin) => bytestream.write_u8(origin.to_raw_repr()),
            Self::AsPath(path) => path.to_bytestream(bytestream),
            Self::NextHop(next_hop) => next_hop.to_bytestream(bytestream),
        }
    }
}

raw_enum! {
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

impl ToBytestream for BgpPathAttributeAsPath {
    type Error = Error;
    fn to_bytestream(&self, bytestream: &mut BytestreamWriter) -> Result<(), Self::Error> {
        if !self.path.is_empty() {
            bytestream.write_u8(self.typ.to_raw_repr())?;
            bytestream.write_u8(self.path.len() as u8)?;
            for seg in &self.path {
                bytestream.write_u32::<BE>(*seg as u32)?;
            }
        }
        Ok(())
    }
}

impl FromBytestream for BgpPathAttributeAsPath {
    type Error = Error;
    fn from_bytestream(bytestream: &mut BytestreamReader) -> Result<Self, Self::Error> {
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
            path.push(as_num as u16)
        }
        Ok(Self { typ, path })
    }
}

raw_enum! {
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

impl ToBytestream for BgpPathAttributeNextHop {
    type Error = Error;
    fn to_bytestream(&self, bytestream: &mut BytestreamWriter) -> Result<(), Self::Error> {
        bytestream.write_all(&self.hop.octets())
    }
}

impl FromBytestream for BgpPathAttributeNextHop {
    type Error = Error;
    fn from_bytestream(bytestream: &mut BytestreamReader) -> Result<Self, Self::Error> {
        Ok(BgpPathAttributeNextHop {
            hop: Ipv4Addr::from(bytestream.read_u32::<BE>()?),
        })
    }
}
