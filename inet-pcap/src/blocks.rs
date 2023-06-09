use bytepack::{
    ByteOrder::LittleEndian, BytestreamWriter, StreamReader, StreamWriter, ToBytestream,
};
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
    fn to_bytestream(&self, w: &mut BytestreamWriter) -> std::result::Result<(), Self::Error> {
        0x0a0d0d0au32.write_to(w, LittleEndian)?;
        let len_marker = w.add_marker(0u32, LittleEndian)?;
        0x1a2b3c4d.write_to(w, LittleEndian)?;
        1u16.write_to(w, LittleEndian)?;
        0u16.write_to(w, LittleEndian)?;
        self.section_len.write_to(w, LittleEndian)?;
        for option in &self.options {
            option.to_bytestream(w)?;
        }
        w.write_all(&[0u8, 0, 0, 0])?;
        let block_len = w.len_since(&len_marker)? as u32 + 12;
        w.write_to_marker(len_marker, block_len)?;
        block_len.write_to(w, LittleEndian)?;
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
                len.write_to(stream, LittleEndian)?;
                stream.write_all(string.as_bytes())?;
                let pad = 4 - len % 4;
                stream.write_all(&vec![0x00; pad as usize])
            }
            Self::OperatingSystem(ref string) => {
                stream.write_all(&[0x03, 0x00])?;
                let len = string.len() as u16;
                len.write_to(stream, LittleEndian)?;
                stream.write_all(string.as_bytes())?;
                let pad = 4 - len % 4;
                stream.write_all(&vec![0x00; pad as usize])
            }
            Self::UserApplication(ref string) => {
                stream.write_all(&[0x04, 0x00])?;
                let len = string.len() as u16;
                len.write_to(stream, LittleEndian)?;
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
        0x1u32.write_to(stream, LittleEndian)?; // Block type IDB
        let len_marker = stream.add_marker(0u32, LittleEndian)?;
        self.link_type.0.write_to(stream, LittleEndian)?;
        0x0u16.write_to(stream, LittleEndian)?; // pad
        self.snap_len.write_to(stream, LittleEndian)?;
        for option in &self.options {
            option.to_bytestream(stream)?;
        }
        let block_len = stream.len_since(&len_marker)? as u32 + 12;
        stream.write_to_marker(len_marker, block_len)?;
        block_len.write_to(stream, LittleEndian)?;

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
                len.write_to(stream, LittleEndian)?;
                stream.write_all(name.as_bytes())?;
                let pad = 4 - len % 4;
                stream.write_all(&vec![0x00; pad as usize])
            }
            Self::InterfaceDescription(ref name) => {
                stream.write_all(&[0x03, 0x00])?;
                let len = name.len() as u16;
                len.write_to(stream, LittleEndian)?;
                stream.write_all(name.as_bytes())?;
                let pad = 4 - len % 4;
                stream.write_all(&vec![0x00; pad as usize])
            }
            Self::OperatingSystem(ref name) => {
                stream.write_all(&[0x0c, 0x00])?;
                let len = name.len() as u16;
                len.write_to(stream, LittleEndian)?;
                stream.write_all(name.as_bytes())?;
                let pad = 4 - len % 4;
                stream.write_all(&vec![0x00; pad as usize])
            }
            Self::Filter(ref kind, ref filter) => {
                stream.write_all(&[0x0c, 0x00])?;
                let len = filter.len() as u16;
                len.write_to(stream, LittleEndian)?;
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

        0x00000006u32.write_to(stream, LittleEndian)?;
        block_len.write_to(stream, LittleEndian)?;

        self.interface_id.write_to(stream, LittleEndian)?;

        let mut bytes = Cursor::new(self.ts.to_be_bytes());
        let upper = u32::read_from(&mut bytes, LittleEndian)?;
        let lower = u32::read_from(&mut bytes, LittleEndian)?;
        stream.write_all(&upper.to_be_bytes())?;
        stream.write_all(&lower.to_be_bytes())?;

        self.cap_len.write_to(stream, LittleEndian)?;
        self.org_len.write_to(stream, LittleEndian)?;

        stream.write_all(&self.data)?;
        stream.write_all(&vec![0u8; data_pad])?;

        block_len.write_to(stream, LittleEndian)?;

        Ok(())
    }
}
