use std::io::{Cursor, Write};

use des::prelude::MessageKind;

pub const MESSAGE_KIND_DHCP: MessageKind = 0x63_82;

// pub(crate) fn merge_str<'a, 'b, 'c: 'a + 'b>(lhs: &'a str, rhs: &'b str) -> &'c str {
//     let l: *const str = lhs;
//     let r: *const str = rhs;

//     let lend = l as *mut u8 as usize + lhs.len();
//     assert!(lend == r as *mut u8 as usize);

//     let res = slice_from_raw_parts(lend as *const u8, lhs.len() + rhs.len());
//     let res = res as *const str;
//     unsafe { &*res }
// }

pub(crate) fn split_off_front(mut buf: Vec<u8>, pos: usize) -> Vec<u8> {
    for i in pos..buf.len() {
        buf[i - pos] = buf[i]
    }
    buf.truncate(buf.len() - pos);
    buf

    // let cap = buf.capacity();
    // let len = buf.len();
    // let ptr = buf.as_mut_ptr();

    // assert!(pos <= len);

    // std::mem::forget(buf);

    // println!("1");
    // // Drop front part
    // drop(unsafe { Vec::from_raw_parts(ptr, pos, pos) });
    // println!("2");

    // let ptr = unsafe { ptr.add(pos) };
    // unsafe { Vec::from_raw_parts(ptr, len - pos, cap - pos) }
}

#[deprecated]
pub trait IntoBytestreamDepc {
    type Error;
    fn into_bytestream(&self, bytestream: &mut Vec<u8>) -> Result<(), Self::Error>;

    fn as_bytestream(&self) -> Result<Vec<u8>, Self::Error> {
        let mut result = Vec::new();
        self.into_bytestream(&mut result)?;
        Ok(result)
    }
}

pub trait IntoBytestream {
    type Error;
    fn into_bytestream(&self, bytestream: &mut impl Write) -> Result<(), Self::Error>;

    fn into_buffer(&self) -> Result<Vec<u8>, Self::Error> {
        let mut buffer = Vec::new();
        self.into_bytestream(&mut buffer)?;
        Ok(buffer)
    }
}

#[deprecated]
pub trait FromBytestreamDepc: Sized {
    type Error;
    fn from_bytestream(bytestream: Vec<u8>) -> Result<Self, Self::Error>;
}

pub trait FromBytestream: Sized {
    type Error;
    fn from_bytestream(bytestream: &mut Cursor<Vec<u8>>) -> Result<Self, Self::Error>;

    fn from_buffer(buffer: Vec<u8>) -> Result<Self, Self::Error> {
        let mut cursor = Cursor::new(buffer);
        Self::from_bytestream(&mut cursor)
    }
}
