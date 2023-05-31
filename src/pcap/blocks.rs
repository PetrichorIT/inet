use bytepack::{ByteOrder::LittleEndian, StreamReader, StreamWriter};
use std::io::{Cursor, Result, Write};

pub(super) struct SHB {
    // block_len: u32,
    // byte_order: u32,
    // major: u16,
    // minor: u16,
    pub(super) section_len: u64,
    pub(super) options: Vec<SHBOption>,
    // block_len the second
}

impl SHB {
    pub(super) fn write_to(&self, w: &mut impl Write) -> Result<()> {
        let mut options = Vec::new();
        for option in &self.options {
            option.write_to(&mut options)?;
        }
        options.extend(&[0x00, 0x00, 0x00, 0x00]);
        let block_len = (options.len() + 28) as u32;

        0x0a0d0d0au32.write_to(w, LittleEndian)?;
        block_len.write_to(w, LittleEndian)?;
        0x1a2b3c4d.write_to(w, LittleEndian)?;
        1u16.write_to(w, LittleEndian)?;
        0u16.write_to(w, LittleEndian)?;
        self.section_len.write_to(w, LittleEndian)?;
        w.write_all(&options)?;
        block_len.write_to(w, LittleEndian)?;
        Ok(())
    }
}

pub(super) enum SHBOption {
    HardwareName(String),
    OperatingSystem(String),
    UserApplication(String),
}

impl SHBOption {
    pub(super) fn write_to(&self, w: &mut impl Write) -> Result<()> {
        match self {
            Self::HardwareName(ref string) => {
                w.write_all(&[0x02, 0x00])?;
                let len = string.len() as u16;
                len.write_to(w, LittleEndian)?;
                w.write_all(string.as_bytes())?;
                let pad = 4 - len % 4;
                w.write_all(&vec![0x00; pad as usize])?;
            }
            Self::OperatingSystem(ref string) => {
                w.write_all(&[0x03, 0x00])?;
                let len = string.len() as u16;
                len.write_to(w, LittleEndian)?;
                w.write_all(string.as_bytes())?;
                let pad = 4 - len % 4;
                w.write_all(&vec![0x00; pad as usize])?;
            }
            Self::UserApplication(ref string) => {
                w.write_all(&[0x04, 0x00])?;
                let len = string.len() as u16;
                len.write_to(w, LittleEndian)?;
                w.write_all(string.as_bytes())?;
                let pad = 4 - len % 4;
                w.write_all(&vec![0x00; pad as usize])?;
            }
        }

        Ok(())
    }
}

pub(super) struct IDB {
    // block_type: u32,
    // block_len: u32,
    pub(super) link_type: u16,
    // reserved 2b
    pub(super) snap_len: u32,
    pub(super) options: Vec<IDBOption>,
}

impl IDB {
    pub(super) fn write_to(&self, w: &mut impl Write) -> Result<()> {
        let mut options = Vec::new();
        for option in &self.options {
            option.write_to(&mut options)?;
        }

        let block_len = (options.len() + 20) as u32;
        0x1u32.write_to(w, LittleEndian)?;
        block_len.write_to(w, LittleEndian)?;
        self.link_type.write_to(w, LittleEndian)?;
        0x0u16.write_to(w, LittleEndian)?;
        self.snap_len.write_to(w, LittleEndian)?;
        w.write_all(&options)?;
        block_len.write_to(w, LittleEndian)?;

        Ok(())
    }
}

#[allow(unused)]
pub(super) enum IDBOption {
    InterfaceName(String),
    InterfaceDescription(String),
    OperatingSystem(String),
    Filter(u8, String),
    TimeResoloutionNanos(),
}

impl IDBOption {
    pub(super) fn write_to(&self, w: &mut impl Write) -> Result<()> {
        match self {
            Self::InterfaceName(ref name) => {
                w.write_all(&[0x02, 0x00])?;
                let len = name.len() as u16;
                len.write_to(w, LittleEndian)?;
                w.write_all(name.as_bytes())?;
                let pad = 4 - len % 4;
                w.write_all(&vec![0x00; pad as usize])?;
            }
            Self::InterfaceDescription(ref name) => {
                w.write_all(&[0x03, 0x00])?;
                let len = name.len() as u16;
                len.write_to(w, LittleEndian)?;
                w.write_all(name.as_bytes())?;
                let pad = 4 - len % 4;
                w.write_all(&vec![0x00; pad as usize])?;
            }
            Self::OperatingSystem(ref name) => {
                w.write_all(&[0x0c, 0x00])?;
                let len = name.len() as u16;
                len.write_to(w, LittleEndian)?;
                w.write_all(name.as_bytes())?;
                let pad = 4 - len % 4;
                w.write_all(&vec![0x00; pad as usize])?;
            }
            Self::Filter(ref kind, ref filter) => {
                w.write_all(&[0x0c, 0x00])?;
                let len = filter.len() as u16;
                len.write_to(w, LittleEndian)?;
                w.write(&[*kind])?;
                w.write_all(filter.as_bytes())?;
                let pad = 4 - len % 4;
                w.write_all(&vec![0x00; pad as usize])?;
            }
            Self::TimeResoloutionNanos() => {
                w.write_all(&[
                    0x09, 0x00, // init
                    0x01, 0x00, // bytelen
                    0x09, // t_resol,
                    0x00, 0x00, 0x00,
                ])?;
            }
        }

        Ok(())
    }
}

pub(super) struct EPB {
    pub(super) interface_id: u32,
    pub(super) ts: u64,
    pub(super) cap_len: u32,
    pub(super) org_len: u32,
    pub(super) data: Vec<u8>,
    // pub(super) options: Vec<()>,
}

impl EPB {
    pub(super) fn write_to(&self, w: &mut impl Write) -> Result<()> {
        let data_len = self.data.len();
        let data_pad = 4 - (data_len % 4);

        let block_len = (data_len + data_pad + 32) as u32;

        0x00000006u32.write_to(w, LittleEndian)?;
        block_len.write_to(w, LittleEndian)?;

        self.interface_id.write_to(w, LittleEndian)?;

        let mut bytes = Cursor::new(self.ts.to_be_bytes());
        let upper = u32::read_from(&mut bytes, LittleEndian)?;
        let lower = u32::read_from(&mut bytes, LittleEndian)?;
        w.write_all(&upper.to_be_bytes())?;
        w.write_all(&lower.to_be_bytes())?;

        self.cap_len.write_to(w, LittleEndian)?;
        self.org_len.write_to(w, LittleEndian)?;

        w.write_all(&self.data)?;
        w.write_all(&vec![0u8; data_pad])?;

        block_len.write_to(w, LittleEndian)?;

        Ok(())
    }
}
