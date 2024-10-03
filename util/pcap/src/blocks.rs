use bytepack::{BytestreamWriter, FromBytestream, ReadBytesExt, ToBytestream, WriteBytesExt, LE};
use std::io::{Cursor, Error, ErrorKind, Read, Write};

use crate::linktype::Linktype;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Block {
    SectionHeaderBlock(SectionHeaderBlock),
    InterfaceDescriptionBlock(InterfaceDescriptionBlock),
    EnhancedPacketBlock(EnhancedPacketBlock),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SectionHeaderBlock {
    pub version_major: u16,
    pub version_minor: u16,
    pub section_len: u64,
    pub options: Vec<SectionHeaderOption>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SectionHeaderOption {
    HardwareName(String),
    OperatingSystem(String),
    UserApplication(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceDescriptionBlock {
    pub link_type: Linktype,
    pub snap_len: u32,
    pub options: Vec<InterfaceDescriptionOption>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InterfaceDescriptionOption {
    InterfaceName(String),
    InterfaceDescription(String),
    OperatingSystem(String),
    Filter(u8, String),
    TimeResoloutionNanos(),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnhancedPacketBlock {
    pub interface_id: u32,
    pub ts: u64,
    pub cap_len: u32,
    pub org_len: u32,
    pub data: Vec<u8>,
}

const BLOCK_TYP_SHB: u32 = 0x0A0D0D0A;
const BLOCK_TYP_IHB: u32 = 0x00000001;
const BLOCK_TYP_EPB: u32 = 0x00000006;

const SHB_MAGIC: u32 = 0x1A2B3C4D;

const SHB_OPTION_HW_NAME: u16 = 0x02;
const SHB_OPTION_OS_NAME: u16 = 0x03;
const SHB_OPTION_USER_APPLICATION: u16 = 0x04;

const IDB_OPTION_IFACE_NAME: u16 = 0x02;
const IDB_OPTION_IFACE_DESC: u16 = 0x03;
const IDB_OPTION_TIME_RESOL: u16 = 0x09;
const IDB_OPTION_FILTER: u16 = 0x0B;
const IDB_OPTION_OS: u16 = 0x0C;

//
// # ToBytestream
//

impl ToBytestream for Block {
    type Error = Error;
    fn to_bytestream(&self, stream: &mut BytestreamWriter) -> Result<(), Self::Error> {
        match self {
            Self::SectionHeaderBlock(shb) => shb.to_bytestream(stream),
            Self::InterfaceDescriptionBlock(idb) => idb.to_bytestream(stream),
            Self::EnhancedPacketBlock(epb) => epb.to_bytestream(stream),
        }
    }
}

impl ToBytestream for SectionHeaderBlock {
    type Error = Error;
    fn to_bytestream(&self, stream: &mut BytestreamWriter) -> std::result::Result<(), Self::Error> {
        write_block(stream, BLOCK_TYP_SHB, |stream| {
            stream.write_u32::<LE>(SHB_MAGIC)?;
            stream.write_u16::<LE>(self.version_major)?;
            stream.write_u16::<LE>(self.version_minor)?;
            stream.write_u64::<LE>(self.section_len)?;
            for option in &self.options {
                option.to_bytestream(stream)?;
            }

            stream.write_all(&[0; 4])?;

            Ok(())
        })
    }
}

impl ToBytestream for SectionHeaderOption {
    type Error = Error;
    fn to_bytestream(&self, stream: &mut BytestreamWriter) -> std::result::Result<(), Self::Error> {
        match self {
            Self::HardwareName(ref string) => {
                stream.write_u16::<LE>(SHB_OPTION_HW_NAME)?;
                let len = string.len() as u16;
                stream.write_u16::<LE>(len)?;
                stream.write_all(string.as_bytes())?;
                let pad = 4 - len % 4;
                stream.write_all(&vec![0x00; pad as usize])
            }
            Self::OperatingSystem(ref string) => {
                stream.write_u16::<LE>(SHB_OPTION_OS_NAME)?;
                let len = string.len() as u16;
                stream.write_u16::<LE>(len)?;
                stream.write_all(string.as_bytes())?;
                let pad = 4 - len % 4;
                stream.write_all(&vec![0x00; pad as usize])
            }
            Self::UserApplication(ref string) => {
                stream.write_u16::<LE>(SHB_OPTION_USER_APPLICATION)?;
                let len = string.len() as u16;
                stream.write_u16::<LE>(len)?;
                stream.write_all(string.as_bytes())?;
                let pad = 4 - len % 4;
                stream.write_all(&vec![0x00; pad as usize])
            }
        }
    }
}

impl ToBytestream for InterfaceDescriptionBlock {
    type Error = Error;
    fn to_bytestream(&self, stream: &mut BytestreamWriter) -> std::result::Result<(), Self::Error> {
        write_block(stream, BLOCK_TYP_IHB, |stream| {
            stream.write_u16::<LE>(self.link_type.0)?;
            stream.write_u16::<LE>(0)?;
            stream.write_u32::<LE>(self.snap_len)?;
            for option in &self.options {
                option.to_bytestream(stream)?;
            }

            Ok(())
        })
    }
}

impl ToBytestream for InterfaceDescriptionOption {
    type Error = Error;
    fn to_bytestream(&self, stream: &mut BytestreamWriter) -> std::result::Result<(), Self::Error> {
        match self {
            Self::InterfaceName(ref name) => {
                stream.write_u16::<LE>(IDB_OPTION_IFACE_NAME)?;
                let len = name.len() as u16;
                stream.write_u16::<LE>(len)?;
                stream.write_all(name.as_bytes())?;
                let pad = 4 - len % 4;
                stream.write_all(&vec![0x00; pad as usize])
            }
            Self::InterfaceDescription(ref name) => {
                stream.write_u16::<LE>(IDB_OPTION_IFACE_DESC)?;
                let len = name.len() as u16;
                stream.write_u16::<LE>(len)?;
                stream.write_all(name.as_bytes())?;
                let pad = 4 - len % 4;
                stream.write_all(&vec![0x00; pad as usize])
            }
            Self::TimeResoloutionNanos() => {
                stream.write_u16::<LE>(IDB_OPTION_TIME_RESOL)?;
                stream.write_all(&[
                    0x01, 0x00, // bytelen
                    0x09, // t_resol,
                    0x00, 0x00, 0x00,
                ])
            }
            Self::Filter(ref kind, ref filter) => {
                stream.write_u16::<LE>(IDB_OPTION_FILTER)?;
                let len = filter.len() as u16;
                stream.write_u16::<LE>(len)?;
                stream.write(&[*kind])?;
                stream.write_all(filter.as_bytes())?;
                let pad = 4 - len % 4;
                stream.write_all(&vec![0x00; pad as usize])
            }
            Self::OperatingSystem(ref name) => {
                stream.write_u16::<LE>(IDB_OPTION_OS)?;
                let len = name.len() as u16;
                stream.write_u16::<LE>(len)?;
                stream.write_all(name.as_bytes())?;
                let pad = 4 - len % 4;
                stream.write_all(&vec![0x00; pad as usize])
            }
        }
    }
}

impl ToBytestream for EnhancedPacketBlock {
    type Error = Error;

    fn to_bytestream(&self, stream: &mut BytestreamWriter) -> std::result::Result<(), Self::Error> {
        write_block(stream, BLOCK_TYP_EPB, |stream| {
            stream.write_u32::<LE>(self.interface_id)?;

            let mut bytes = Cursor::new(self.ts.to_be_bytes());
            let upper = bytes.read_u32::<LE>()?;
            let lower = bytes.read_u32::<LE>()?;
            stream.write_all(&upper.to_be_bytes())?;
            stream.write_all(&lower.to_be_bytes())?;

            stream.write_u32::<LE>(self.cap_len)?;
            stream.write_u32::<LE>(self.org_len)?;

            let data_pad = 4 - (self.data.len() % 4);

            stream.write_all(&self.data)?;
            stream.write_all(&vec![0u8; data_pad])?;

            Ok(())
        })
    }
}

fn write_block(
    stream: &mut bytepack::BytestreamWriter,
    block_typ: u32,
    f: impl FnOnce(&mut bytepack::BytestreamWriter) -> Result<(), Error>,
) -> Result<(), Error> {
    stream.write_u32::<LE>(block_typ)?;
    let len_marker = stream.create_typed_marker::<u32>()?;
    f(stream)?;

    let block_len = stream.len_since_marker(&len_marker) as u32 + 12;
    stream
        .update_marker(&len_marker)
        .write_u32::<LE>(block_len)?;
    stream.write_u32::<LE>(block_len)?;

    Ok(())
}

//
// # FromBytestream
//

impl FromBytestream for Block {
    type Error = Error;
    fn from_bytestream(stream: &mut bytepack::BytestreamReader) -> Result<Self, Self::Error> {
        let block_type = stream.read_u32::<LE>()?;
        stream.bump_back(4);

        Ok(match block_type {
            BLOCK_TYP_SHB => Self::SectionHeaderBlock(SectionHeaderBlock::from_bytestream(stream)?),
            BLOCK_TYP_IHB => {
                Self::InterfaceDescriptionBlock(InterfaceDescriptionBlock::from_bytestream(stream)?)
            }
            BLOCK_TYP_EPB => {
                Self::EnhancedPacketBlock(EnhancedPacketBlock::from_bytestream(stream)?)
            }
            _ => unreachable!(),
        })
    }
}

impl FromBytestream for SectionHeaderBlock {
    type Error = Error;
    fn from_bytestream(stream: &mut bytepack::BytestreamReader) -> Result<Self, Self::Error> {
        read_block(stream, BLOCK_TYP_SHB, |body| {
            let byteorder_magic = body.read_u32::<LE>()?;
            assert_eq!(byteorder_magic, SHB_MAGIC);
            let version_major = body.read_u16::<LE>()?;
            let version_minor = body.read_u16::<LE>()?;
            let section_len = body.read_u64::<LE>()?;

            // read options
            let mut options = Vec::new();
            loop {
                match SectionHeaderOption::from_bytestream(body) {
                    Ok(v) => options.push(v),
                    Err(e) if e.kind() == ErrorKind::UnexpectedEof => break,
                    Err(e) => return Err(e),
                }
            }

            Ok(SectionHeaderBlock {
                section_len,
                version_major,
                version_minor,
                options,
            })
        })
    }
}

impl FromBytestream for SectionHeaderOption {
    type Error = Error;
    fn from_bytestream(stream: &mut bytepack::BytestreamReader) -> Result<Self, Self::Error> {
        let typ = stream.read_u16::<LE>()?;
        let len = stream.read_u16::<LE>()?;
        let pad = 4 - (len % 4);

        let mut option = stream.extract(len as usize)?;
        let result = match typ {
            0 => {
                assert_eq!(len, 0);
                return Err(Error::new(ErrorKind::UnexpectedEof, "EOO"));
            }
            2 => {
                let mut str = String::new();
                option.read_to_string(&mut str)?;
                Self::HardwareName(str)
            }
            3 => {
                let mut str = String::new();
                option.read_to_string(&mut str)?;
                Self::OperatingSystem(str)
            }
            4 => {
                let mut str = String::new();
                option.read_to_string(&mut str)?;
                Self::UserApplication(str)
            }
            _ => todo!("{typ}"),
        };

        stream.read_exact(&mut vec![0; pad as usize])?;

        Ok(result)
    }
}

impl FromBytestream for InterfaceDescriptionBlock {
    type Error = Error;
    fn from_bytestream(stream: &mut bytepack::BytestreamReader) -> Result<Self, Self::Error> {
        read_block(stream, BLOCK_TYP_IHB, |body| {
            let link_type = Linktype(body.read_u16::<LE>()?);
            let resv = body.read_u16::<LE>()?;
            assert_eq!(resv, 0);
            let snap_len = body.read_u32::<LE>()?;

            let mut options = Vec::new();
            loop {
                match InterfaceDescriptionOption::from_bytestream(body) {
                    Ok(v) => options.push(v),
                    Err(e) if e.kind() == ErrorKind::UnexpectedEof => break,
                    Err(e) => return Err(e),
                }
            }

            Ok(InterfaceDescriptionBlock {
                link_type,
                snap_len,
                options,
            })
        })
    }
}

impl FromBytestream for InterfaceDescriptionOption {
    type Error = Error;
    fn from_bytestream(stream: &mut bytepack::BytestreamReader) -> Result<Self, Self::Error> {
        let typ = stream.read_u16::<LE>()?;
        let len = stream.read_u16::<LE>()?;
        let pad = 4 - (len % 4);

        let mut option = stream.extract(len as usize)?;
        let result = match typ {
            0 => {
                assert_eq!(len, 0);
                return Err(Error::new(ErrorKind::UnexpectedEof, "EOO"));
            }
            0x2 => {
                let mut str = String::new();
                option.read_to_string(&mut str)?;
                Self::InterfaceName(str)
            }
            0x3 => {
                let mut str = String::new();
                option.read_to_string(&mut str)?;
                Self::InterfaceDescription(str)
            }
            0x9 => {
                // TODO
                stream.read_exact(&mut [0; 4])?;
                Self::TimeResoloutionNanos()
            }
            0xb => {
                let kind = option.read_u8()?;
                let mut str = String::new();
                option.read_to_string(&mut str)?;
                Self::Filter(kind, str)
            }
            0xc => {
                let mut str = String::new();
                option.read_to_string(&mut str)?;
                Self::OperatingSystem(str)
            }
            _ => todo!("{typ}"),
        };

        stream.read_exact(&mut vec![0; pad as usize])?;

        Ok(result)
    }
}

impl FromBytestream for EnhancedPacketBlock {
    type Error = Error;

    fn from_bytestream(stream: &mut bytepack::BytestreamReader) -> Result<Self, Self::Error> {
        read_block(stream, BLOCK_TYP_EPB, |body| {
            let interface_id = body.read_u32::<LE>()?;

            let upper = body.read_u32::<LE>()?.to_le_bytes();
            let lower = body.read_u32::<LE>()?.to_le_bytes();
            let ts = u64::from_be_bytes([
                upper[0], upper[1], upper[2], upper[3], lower[0], lower[1], lower[2], lower[3],
            ]);

            let cap_len = body.read_u32::<LE>()?;
            let org_len = body.read_u32::<LE>()?;

            let mut data = Vec::new();
            body.read_to_end(&mut data)?;
            data.truncate(cap_len as usize);

            Ok(EnhancedPacketBlock {
                interface_id,
                ts,
                cap_len,
                org_len,
                data,
            })
        })
    }
}

fn read_block<R>(
    stream: &mut bytepack::BytestreamReader,
    block_typ: u32,
    f: impl FnOnce(&mut bytepack::BytestreamReader) -> Result<R, Error>,
) -> Result<R, Error> {
    let read_block_typ = stream.read_u32::<LE>()?;
    if read_block_typ != block_typ {
        return Err(Error::new(ErrorKind::InvalidInput, "unexpected block typ"));
    }

    let block_len = stream.read_u32::<LE>()?;
    let pad = block_len % 4;
    let mut body = stream.extract((block_len + pad - 12) as usize)?;

    let result = f(&mut body);

    let block_len_redundant = stream.read_u32::<LE>()?;
    if block_len != block_len_redundant {
        return Err(Error::new(ErrorKind::Other, "total block len error"));
    }

    result
}
