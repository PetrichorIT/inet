use bytepack::{BytestreamReader, BytestreamWriter, FromBytestream, ToBytestream};
use des::runtime::random;

use std::{
    fmt::Display,
    io::{Read, Write},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MacAddress([u8; 6]);

impl MacAddress {
    pub const NULL: MacAddress = MacAddress([0; 6]);
    pub const BROADCAST: MacAddress = MacAddress([0xff; 6]);

    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    #[must_use]
    pub fn gen() -> MacAddress {
        let mut mac = random::<[u8; 6]>();
        mac[0] &= 0b1111_1110;
        MacAddress(mac)
    }

    #[must_use]
    pub fn is_unspecified(&self) -> bool {
        *self == MacAddress::NULL
    }

    #[must_use]
    pub fn is_broadcast(&self) -> bool {
        *self == MacAddress::BROADCAST
    }
}

impl From<[u8; 6]> for MacAddress {
    fn from(value: [u8; 6]) -> Self {
        MacAddress(value)
    }
}

impl From<MacAddress> for [u8; 6] {
    fn from(value: MacAddress) -> Self {
        value.0
    }
}

impl ToBytestream for MacAddress {
    type Error = std::io::Error;
    fn to_bytestream(&self, bytestream: &mut BytestreamWriter) -> Result<(), Self::Error> {
        // BigEndian since as byte array
        bytestream.write_all(&self.0)
    }
}

impl FromBytestream for MacAddress {
    type Error = std::io::Error;
    fn from_bytestream(bytestream: &mut BytestreamReader) -> Result<Self, Self::Error> {
        let mut bytes = [0u8; 6];
        bytestream.read_exact(&mut bytes)?;
        Ok(MacAddress(bytes))
    }
}

impl Display for MacAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}
