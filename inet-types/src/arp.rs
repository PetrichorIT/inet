#![allow(clippy::similar_names)]

use super::iface::MacAddress;
use bytepack::FromBytestream;
use bytepack::{
    ByteOrder::BigEndian, BytestreamReader, BytestreamWriter, StreamReader, StreamWriter,
    ToBytestream,
};

use des::prelude::*;
use std::io::Read;
use std::{io::Write, net::Ipv4Addr};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ArpPacket {
    pub htype: u16,
    pub ptype: u16,
    haddrlen: u8,
    paddrlen: u8,
    pub operation: ARPOperation,
    raw: Vec<u8>,
}

impl ArpPacket {
    // Read only

    #[must_use]
    pub fn is_ipv4_ethernet(&self) -> bool {
        self.htype == 1 && self.ptype == 0x0800
    }

    #[must_use]
    pub fn is_ipv6_ethernet(&self) -> bool {
        self.htype == 1 && self.ptype == 0x86DD
    }

    #[must_use]
    pub fn src_haddr(&self) -> &[u8] {
        &self.raw[0..self.haddrlen as usize]
    }

    #[must_use]
    pub fn src_paddr(&self) -> &[u8] {
        let s = self.haddrlen as usize;
        &self.raw[s..(s + self.paddrlen as usize)]
    }

    #[must_use]
    pub fn dst_haddr(&self) -> &[u8] {
        let s = (self.haddrlen + self.paddrlen) as usize;
        &self.raw[s..(s + self.haddrlen as usize)]
    }

    #[must_use]
    pub fn dst_paddr(&self) -> &[u8] {
        let s = (2 * self.haddrlen + self.paddrlen) as usize;
        &self.raw[s..(s + self.paddrlen as usize)]
    }

    // Ethernet

    #[must_use]
    pub fn src_mac_addr(&self) -> MacAddress {
        let bytes: [u8; 6] = self
            .src_haddr()
            .try_into()
            .expect("Failed to cast as ethernet addr");
        MacAddress::from(bytes)
    }

    #[must_use]
    pub fn dest_mac_addr(&self) -> MacAddress {
        let bytes: [u8; 6] = self
            .dst_haddr()
            .try_into()
            .expect("Failed to cast as ethernet addr");
        MacAddress::from(bytes)
    }

    // Ip

    #[must_use]
    pub fn src_ip_addr(&self) -> IpAddr {
        if self.is_ipv4_ethernet() {
            self.src_ipv4_addr().into()
        } else {
            self.src_ipv6_addr().into()
        }
    }

    #[must_use]
    pub fn dest_ip_addr(&self) -> IpAddr {
        if self.is_ipv4_ethernet() {
            self.dest_ipv4_addr().into()
        } else {
            self.dest_ipv6_addr().into()
        }
    }

    // Ipv4

    #[must_use]
    pub fn src_ipv4_addr(&self) -> Ipv4Addr {
        let bytes: [u8; 4] = self
            .src_paddr()
            .try_into()
            .expect("Failed to cast as ip addr");
        Ipv4Addr::from(bytes)
    }

    #[must_use]
    pub fn dest_ipv4_addr(&self) -> Ipv4Addr {
        let bytes: [u8; 4] = self
            .dst_paddr()
            .try_into()
            .expect("Failed to cast as ip addr");
        Ipv4Addr::from(bytes)
    }

    // Ipv6

    #[must_use]
    pub fn src_ipv6_addr(&self) -> Ipv6Addr {
        let bytes: [u8; 16] = self
            .src_paddr()
            .try_into()
            .expect("Failed to cast as ip addr");
        Ipv6Addr::from(bytes)
    }

    #[must_use]
    pub fn dest_ipv6_addr(&self) -> Ipv6Addr {
        let bytes: [u8; 16] = self
            .dst_paddr()
            .try_into()
            .expect("Failed to cast as ip addr");
        Ipv6Addr::from(bytes)
    }

    // Write interfaces

    fn dst_paddr_mut(&mut self) -> &mut [u8] {
        let s = (self.haddrlen + self.paddrlen) as usize;
        &mut self.raw[s..(s + self.haddrlen as usize)]
    }

    #[must_use]
    pub fn new_request(src_haddr: MacAddress, src_paddr: IpAddr, dst_paddr: IpAddr) -> Self {
        use IpAddr::{V4, V6};
        match (src_paddr, dst_paddr) {
            (V4(src), V4(dst)) => Self::new_v4_request(src_haddr, src, dst),
            (V6(src), V6(dst)) => Self::new_v6_request(src_haddr, src, dst),
            _ => unreachable!(),
        }
    }

    #[must_use]
    pub fn new_v4_request(src_haddr: MacAddress, src_paddr: Ipv4Addr, dst_paddr: Ipv4Addr) -> Self {
        let mut raw = Vec::with_capacity(20);
        raw.extend(src_haddr.as_slice());
        raw.extend(src_paddr.octets());
        raw.extend(MacAddress::NULL.as_slice());
        raw.extend(dst_paddr.octets());
        Self {
            htype: 0x0001,
            ptype: 0x0800,
            haddrlen: 6,
            paddrlen: 4,
            operation: ARPOperation::Request,
            raw,
        }
    }

    #[must_use]
    pub fn new_v6_request(src_haddr: MacAddress, src_paddr: Ipv6Addr, dst_paddr: Ipv6Addr) -> Self {
        let mut raw = Vec::with_capacity(44);
        raw.extend(src_haddr.as_slice());
        raw.extend(src_paddr.octets());
        raw.extend(MacAddress::NULL.as_slice());
        raw.extend(dst_paddr.octets());
        Self {
            htype: 0x0001,
            ptype: 0x86DD,
            haddrlen: 6,
            paddrlen: 16,
            operation: ARPOperation::Request,
            raw,
        }
    }

    #[must_use]
    pub fn into_response(&self, dest_haddr: MacAddress) -> Self {
        let mut resp = self.clone();
        resp.operation = ARPOperation::Response;
        let buf = resp.dst_paddr_mut();
        buf[..6].copy_from_slice(&dest_haddr.as_slice()[..6]);
        resp
    }
}

impl ToBytestream for ArpPacket {
    type Error = std::io::Error;
    fn to_bytestream(&self, bytestream: &mut BytestreamWriter) -> Result<(), Self::Error> {
        self.htype.write_to(bytestream, BigEndian)?;
        self.ptype.write_to(bytestream, BigEndian)?;
        self.haddrlen.write_to(bytestream, BigEndian)?;
        self.paddrlen.write_to(bytestream, BigEndian)?;

        self.operation.to_bytestream(bytestream)?;

        bytestream.write_all(&self.raw)
    }
}

impl FromBytestream for ArpPacket {
    type Error = std::io::Error;
    fn from_bytestream(bytestream: &mut BytestreamReader) -> Result<Self, Self::Error> {
        let htype = u16::read_from(bytestream, BigEndian)?;
        let ptype = u16::read_from(bytestream, BigEndian)?;

        let haddrlen = u8::read_from(bytestream, BigEndian)?;
        let paddrlen = u8::read_from(bytestream, BigEndian)?;
        let operation = ARPOperation::from_bytestream(bytestream)?;

        let size = 2 * haddrlen + 2 * paddrlen;
        let mut buf = vec![0u8; size as usize];
        bytestream.read_exact(&mut buf)?;

        Ok(ArpPacket {
            htype,
            ptype,
            haddrlen,
            paddrlen,
            operation,
            raw: buf,
        })
    }
}

impl MessageBody for ArpPacket {
    fn byte_len(&self) -> usize {
        self.raw.len() + 8
    }
}

pub const KIND_ARP: MessageKind = 0x0806;

primitve_enum_repr! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub enum ARPOperation {
        type Repr = u16;

        Request = 1,
        Response = 2,
    };
}

impl ToBytestream for ARPOperation {
    type Error = std::io::Error;
    fn to_bytestream(&self, bytestream: &mut BytestreamWriter) -> Result<(), Self::Error> {
        self.to_raw().write_to(bytestream, BigEndian)
    }
}

impl FromBytestream for ARPOperation {
    type Error = std::io::Error;
    fn from_bytestream(bytestream: &mut BytestreamReader) -> Result<Self, Self::Error> {
        let tag = u16::read_from(bytestream, BigEndian)?;
        Ok(Self::from_raw(tag).unwrap())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_ethernet_request() {
        let r = ArpPacket::new_v4_request(
            [1, 2, 3, 4, 5, 6].into(),
            Ipv4Addr::new(1, 2, 3, 4),
            Ipv4Addr::new(255, 254, 253, 252),
        );

        assert_eq!(r.htype, 1);
        assert_eq!(r.ptype, 0x0800);
        assert_eq!(r.src_mac_addr(), [1, 2, 3, 4, 5, 6].into());
        assert_eq!(r.dest_mac_addr(), [0, 0, 0, 0, 0, 0].into());
        assert_eq!(r.src_ipv4_addr(), Ipv4Addr::new(1, 2, 3, 4));
        assert_eq!(r.dest_ipv4_addr(), Ipv4Addr::new(255, 254, 253, 252));

        let r = ArpPacket::from_buffer(r.to_buffer().unwrap()).unwrap();
        assert_eq!(r.htype, 1);
        assert_eq!(r.ptype, 0x0800);
        assert_eq!(r.src_mac_addr(), [1, 2, 3, 4, 5, 6].into());
        assert_eq!(r.dest_mac_addr(), [0, 0, 0, 0, 0, 0].into());
        assert_eq!(r.src_ipv4_addr(), Ipv4Addr::new(1, 2, 3, 4));
        assert_eq!(r.dest_ipv4_addr(), Ipv4Addr::new(255, 254, 253, 252));
    }

    #[test]
    fn ipv6_ethernet_request() {
        let r = ArpPacket::new_v6_request(
            [1, 2, 3, 4, 5, 6].into(),
            Ipv6Addr::new(1, 2, 3, 4, 5, 6, 7, 8),
            Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0),
        );

        assert_eq!(r.htype, 1);
        assert_eq!(r.ptype, 0x86DD);
        assert_eq!(r.src_mac_addr(), [1, 2, 3, 4, 5, 6].into());
        assert_eq!(r.dest_mac_addr(), [0, 0, 0, 0, 0, 0].into());
        assert_eq!(r.src_ipv6_addr(), Ipv6Addr::new(1, 2, 3, 4, 5, 6, 7, 8));
        assert_eq!(r.dest_ipv6_addr(), Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0));

        let r = ArpPacket::from_buffer(r.to_buffer().unwrap()).unwrap();
        assert_eq!(r.htype, 1);
        assert_eq!(r.ptype, 0x86DD);
        assert_eq!(r.src_mac_addr(), [1, 2, 3, 4, 5, 6].into());
        assert_eq!(r.dest_mac_addr(), [0, 0, 0, 0, 0, 0].into());
        assert_eq!(r.src_ipv6_addr(), Ipv6Addr::new(1, 2, 3, 4, 5, 6, 7, 8));
        assert_eq!(r.dest_ipv6_addr(), Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0));
    }
}
