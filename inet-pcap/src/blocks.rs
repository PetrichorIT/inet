use bytepack::{BytestreamWriter, ReadBytesExt, ToBytestream, WriteBytesExt, LE};
use std::io::{Cursor, Error, Write};

use crate::linktype::Linktype;

pub(crate) struct SHB {
    // block_len: u32,
    // byte_order: u32,
    // major: u16,
    // minor: u16,
    pub section_len: u64,
    pub options: Vec<SHBOption>,
    // block_len the second
}

impl ToBytestream for SHB {
    type Error = Error;
    fn to_bytestream(&self, stream: &mut BytestreamWriter) -> std::result::Result<(), Self::Error> {
        stream.write_u32::<LE>(0x0a0d0d0a)?;
        let len_marker = stream.create_typed_marker::<u32>()?;

        stream.write_u32::<LE>(0x1a2b3c4d)?;
        stream.write_u16::<LE>(1)?;
        stream.write_u16::<LE>(0)?;
        stream.write_u64::<LE>(self.section_len)?;
        for option in &self.options {
            option.to_bytestream(stream)?;
        }

        stream.write_all(&[0u8, 0, 0, 0])?;
        let block_len = stream.len_since_marker(&len_marker) as u32 + 12;
        stream
            .update_marker(&len_marker)
            .write_u32::<LE>(block_len)?;
        stream.write_u32::<LE>(block_len)?;

        Ok(())
    }
}

pub(crate) enum SHBOption {
    HardwareName(String),
    OperatingSystem(String),
    UserApplication(String),
}

impl ToBytestream for SHBOption {
    type Error = Error;
    fn to_bytestream(&self, stream: &mut BytestreamWriter) -> std::result::Result<(), Self::Error> {
        match self {
            Self::HardwareName(ref string) => {
                stream.write_all(&[0x02, 0x00])?;
                let len = string.len() as u16;
                stream.write_u16::<LE>(len)?;
                stream.write_all(string.as_bytes())?;
                let pad = 4 - len % 4;
                stream.write_all(&vec![0x00; pad as usize])
            }
            Self::OperatingSystem(ref string) => {
                stream.write_all(&[0x03, 0x00])?;
                let len = string.len() as u16;
                stream.write_u16::<LE>(len)?;
                stream.write_all(string.as_bytes())?;
                let pad = 4 - len % 4;
                stream.write_all(&vec![0x00; pad as usize])
            }
            Self::UserApplication(ref string) => {
                stream.write_all(&[0x04, 0x00])?;
                let len = string.len() as u16;
                stream.write_u16::<LE>(len)?;
                stream.write_all(string.as_bytes())?;
                let pad = 4 - len % 4;
                stream.write_all(&vec![0x00; pad as usize])
            }
        }
    }
}

pub(crate) struct IDB {
    // block_type: u32,
    // block_len: u32,
    pub link_type: Linktype,
    // reserved 2b
    pub snap_len: u32,
    pub options: Vec<IDBOption>,
}

impl ToBytestream for IDB {
    type Error = Error;
    fn to_bytestream(&self, stream: &mut BytestreamWriter) -> std::result::Result<(), Self::Error> {
        stream.write_u32::<LE>(1)?;
        let len_marker = stream.create_typed_marker::<u32>()?;
        stream.write_u16::<LE>(self.link_type.0)?;
        stream.write_u16::<LE>(0)?;
        stream.write_u32::<LE>(self.snap_len)?;
        for option in &self.options {
            option.to_bytestream(stream)?;
        }

        let block_len = stream.len_since_marker(&len_marker) as u32 + 12;
        stream
            .update_marker(&len_marker)
            .write_u32::<LE>(block_len)?;
        stream.write_u32::<LE>(block_len)?;

        Ok(())
    }
}

#[allow(unused)]
pub(crate) enum IDBOption {
    InterfaceName(String),
    InterfaceDescription(String),
    OperatingSystem(String),
    Filter(u8, String),
    TimeResoloutionNanos(),
}

impl ToBytestream for IDBOption {
    type Error = Error;
    fn to_bytestream(&self, stream: &mut BytestreamWriter) -> std::result::Result<(), Self::Error> {
        match self {
            Self::InterfaceName(ref name) => {
                stream.write_all(&[0x02, 0x00])?;
                let len = name.len() as u16;
                stream.write_u16::<LE>(len)?;
                stream.write_all(name.as_bytes())?;
                let pad = 4 - len % 4;
                stream.write_all(&vec![0x00; pad as usize])
            }
            Self::InterfaceDescription(ref name) => {
                stream.write_all(&[0x03, 0x00])?;
                let len = name.len() as u16;
                stream.write_u16::<LE>(len)?;
                stream.write_all(name.as_bytes())?;
                let pad = 4 - len % 4;
                stream.write_all(&vec![0x00; pad as usize])
            }
            Self::OperatingSystem(ref name) => {
                stream.write_all(&[0x0c, 0x00])?;
                let len = name.len() as u16;
                stream.write_u16::<LE>(len)?;
                stream.write_all(name.as_bytes())?;
                let pad = 4 - len % 4;
                stream.write_all(&vec![0x00; pad as usize])
            }
            Self::Filter(ref kind, ref filter) => {
                stream.write_all(&[0x0c, 0x00])?;
                let len = filter.len() as u16;
                stream.write_u16::<LE>(len)?;
                stream.write(&[*kind])?;
                stream.write_all(filter.as_bytes())?;
                let pad = 4 - len % 4;
                stream.write_all(&vec![0x00; pad as usize])
            }
            Self::TimeResoloutionNanos() => {
                stream.write_all(&[
                    0x09, 0x00, // init
                    0x01, 0x00, // bytelen
                    0x09, // t_resol,
                    0x00, 0x00, 0x00,
                ])
            }
        }
    }
}

pub(crate) struct EPB {
    pub interface_id: u32,
    pub ts: u64,
    pub cap_len: u32,
    pub org_len: u32,
    pub data: Vec<u8>,
    // pub(super) options: Vec<()>,
}

impl ToBytestream for EPB {
    type Error = Error;

    fn to_bytestream(&self, stream: &mut BytestreamWriter) -> std::result::Result<(), Self::Error> {
        let data_len = self.data.len();
        let data_pad = 4 - (data_len % 4);

        let block_len = (data_len + data_pad + 32) as u32;

        stream.write_u32::<LE>(6)?;
        stream.write_u32::<LE>(block_len)?;

        stream.write_u32::<LE>(self.interface_id)?;

        let mut bytes = Cursor::new(self.ts.to_be_bytes());
        let upper = bytes.read_u32::<LE>()?;
        let lower = bytes.read_u32::<LE>()?;
        stream.write_all(&upper.to_be_bytes())?;
        stream.write_all(&lower.to_be_bytes())?;

        stream.write_u32::<LE>(self.cap_len)?;
        stream.write_u32::<LE>(self.org_len)?;

        stream.write_all(&self.data)?;
        stream.write_all(&vec![0u8; data_pad])?;

        stream.write_u32::<LE>(block_len)?;

        Ok(())
    }
}
