use std::{
    io::{Cursor, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

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
    fn from_bytestream(bytestream: &mut Cursor<impl AsRef<[u8]>>) -> Result<Self, Self::Error>;

    fn from_buffer(buffer: impl AsRef<[u8]>) -> Result<Self, Self::Error> {
        let mut cursor = Cursor::new(buffer);
        Self::from_bytestream(&mut cursor)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IpMask {
    V4(Ipv4Mask),
    V6(Ipv6Mask),
}

impl IpMask {
    pub const fn catch_all_v4() -> Self {
        Self::V4(Ipv4Mask::catch_all())
    }

    pub const fn catch_all_v6() -> Self {
        Self::V6(Ipv6Mask::catch_all())
    }

    pub fn matches(&self, ip: IpAddr) -> bool {
        match self {
            Self::V4(mask) => {
                let IpAddr::V4(v4) = ip else { return false };
                mask.matches(v4)
            }
            Self::V6(mask) => {
                let IpAddr::V6(v6) = ip else { return false };
                mask.matches(v6)
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ipv4Mask {
    ip: Ipv4Addr,
    mask: Ipv4Addr,
}

impl Ipv4Mask {
    pub const fn new(ip: Ipv4Addr, mask: Ipv4Addr) -> Self {
        Self { ip, mask }
    }

    pub const fn catch_all() -> Self {
        Self::new(Ipv4Addr::UNSPECIFIED, Ipv4Addr::UNSPECIFIED)
    }

    pub fn matches(&self, ip: Ipv4Addr) -> bool {
        let mask = u32::from(self.ip) & u32::from(self.mask);
        let ip = u32::from(ip) & u32::from(self.mask);
        mask == ip
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ipv6Mask {
    ip: Ipv6Addr,
    mask: Ipv6Addr,
}

impl Ipv6Mask {
    pub const fn new(ip: Ipv6Addr, mask: Ipv6Addr) -> Self {
        Self { ip, mask }
    }

    pub const fn catch_all() -> Self {
        Self::new(Ipv6Addr::UNSPECIFIED, Ipv6Addr::UNSPECIFIED)
    }

    pub fn matches(&self, ip: Ipv6Addr) -> bool {
        let mask = u128::from(self.ip) & u128::from(self.mask);
        let ip = u128::from(ip) & u128::from(self.mask);
        mask == ip
    }
}

// pub struct Array<T, const N: usize> {
//     array: [Option<T>; N],
//     len: usize,
// }

// impl<T, const N: usize> Array<T, N> {
//     const INIT: Option<T> = None;
//     pub const fn new() -> Self {
//         Self {
//             array: [Self::INIT; N],
//             len: 0,
//         }
//     }

//     pub fn truncate(&mut self, len: usize) {
//         assert!(len < N);
//         if len > self.len {
//             return;
//         }
//         for i in len..self.len {
//             self.array[i] = None;
//         }
//         self.len = len;
//     }

//     pub fn len(&self) -> usize {
//         self.len
//     }

//     pub fn is_empty(&self) -> bool {
//         self.len == 0
//     }

//     pub fn as_slice(&self) -> &[T] {
//         self.array.as_slice().map(|v| v.as_ref().unwrap())
//     }
// }
