use std::{io::Cursor, net::Ipv4Addr};

use bytestream::{ByteOrder::BigEndian, StreamReader, StreamWriter};
use des::{prelude::MessageBody, runtime::random};
use types::{iface::MacAddress, FromBytestream, IntoBytestream};

use crate::utils::get_mac_address;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DHCPMessage {
    pub op: DHCPOp, // op code
    pub htype: u8,  // hardware type (e.g. ethernet) - ARP
    pub hlen: u8,   // hardware address len - ARP
    pub hops: u8,   // hardware options - ARP

    pub xid: u32, // transaction id (client choosen)

    pub secs: u16,  // secs since address aquisition started (client set)
    pub flags: u16, // flags

    pub ciaddr: Ipv4Addr,   // client ip addr, only at BOUND, RENEW, REBIND
    pub yiaddr: Ipv4Addr,   // ip addr for client
    pub siaddr: Ipv4Addr,   // ip addr of next server in bootstrap
    pub giaddr: Ipv4Addr,   // relay ip addr
    pub chaddr: MacAddress, // client hardware address
    // pub sname: [u8; 64],  // server host name
    // pub file: [u8; 128],  // boot file name
    pub ops: DHCPOps,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, MessageBody)]
#[repr(u8)]
pub enum DHCPOp {
    BootRequest = 1,
    BootReply = 2,

    Wakeup = 3,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, MessageBody)]
pub struct DHCPOps {
    pub typ: DHCPOpsTyp,
    pub pars: Vec<DHCPParameter>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, MessageBody)]
#[repr(u8)]
pub enum DHCPOpsTyp {
    Discover = 1,
    Offer = 2,
    Request = 3,
    Ack = 4,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, MessageBody)]
#[repr(u8)]
pub enum DHCPParameter {
    ReqSubnetMask,
    SubnetMask(Ipv4Addr),
    ReqRouter,
    Router(Ipv4Addr),
    ReqDomainName,
    DomainName(),
    ReqDomainNameServer,
    DomainNameServer(Ipv4Addr),
    //
    AddressRequested(Ipv4Addr),
    Server(Ipv4Addr),
}

impl DHCPMessage {
    pub fn wakeup() -> DHCPMessage {
        Self {
            op: DHCPOp::Wakeup,

            htype: 0x01,
            hlen: 0x06,
            hops: 0x00,

            xid: 0x0000_0000,

            secs: 0x0000,
            flags: 0x0000,

            ciaddr: Ipv4Addr::UNSPECIFIED,
            yiaddr: Ipv4Addr::UNSPECIFIED,
            siaddr: Ipv4Addr::UNSPECIFIED,
            giaddr: Ipv4Addr::UNSPECIFIED,

            chaddr: MacAddress::NULL,
            ops: DHCPOps {
                typ: DHCPOpsTyp::Discover,
                pars: Vec::new(),
            },
        }
    }

    /// Creates a DHCP DISCOVER message.
    ///
    /// Send with src: 0.0.0.0:68 dest:255.255.255.255:67
    /// eth: client_addr -> ff:ff:ff:ff:ff:ff
    pub fn discover(req_addr: Option<Ipv4Addr>) -> DHCPMessage {
        let mac = get_mac_address()
            .expect("Failed to fetch hardware address")
            .expect("Module has no hardware address");

        let mut ops = vec![
            DHCPParameter::ReqSubnetMask,
            DHCPParameter::ReqRouter,
            DHCPParameter::ReqDomainName,
            DHCPParameter::ReqDomainNameServer,
        ];
        if let Some(addr) = req_addr {
            ops.push(DHCPParameter::AddressRequested(addr))
        }

        DHCPMessage {
            op: DHCPOp::BootRequest,
            htype: 0x01,
            hlen: 0x06,
            hops: 0x00,
            xid: random::<u32>(),
            secs: 0x0000,
            flags: 0x0000,
            ciaddr: Ipv4Addr::UNSPECIFIED,
            yiaddr: Ipv4Addr::UNSPECIFIED,
            siaddr: Ipv4Addr::UNSPECIFIED,
            giaddr: Ipv4Addr::UNSPECIFIED,
            chaddr: mac,
            // sname: [0; 64],
            // file: [0; 128],
            ops: DHCPOps {
                typ: DHCPOpsTyp::Discover,
                pars: ops,
            },
        }
    }

    /// Creates an offer
    ///
    /// Full headers
    pub fn offer(
        discover: DHCPMessage,
        server_ip: Ipv4Addr,
        assigned_ip: Ipv4Addr,
        ops_response: Vec<DHCPParameter>,
    ) -> DHCPMessage {
        DHCPMessage {
            op: DHCPOp::BootReply,
            htype: 0x01,
            hlen: 0x06,
            hops: 0x00,
            xid: discover.xid,
            secs: 0x0000,
            flags: 0x0000,
            ciaddr: discover.ciaddr,
            yiaddr: assigned_ip,
            siaddr: server_ip,
            giaddr: Ipv4Addr::UNSPECIFIED,
            chaddr: discover.chaddr,
            // sname: [0; 64],
            // file: [0; 128],
            ops: DHCPOps {
                typ: DHCPOpsTyp::Offer,
                pars: ops_response,
            },
        }
    }

    pub fn request(offer: DHCPMessage) -> DHCPMessage {
        DHCPMessage {
            op: DHCPOp::BootRequest,
            htype: 0x01,
            hlen: 0x06,
            hops: 0x00,
            xid: offer.xid,
            secs: 0x00,
            flags: 0x0000,
            ciaddr: offer.yiaddr,
            yiaddr: Ipv4Addr::UNSPECIFIED,
            siaddr: offer.siaddr,
            giaddr: Ipv4Addr::UNSPECIFIED,
            chaddr: offer.chaddr,
            // sname: [0; 64],
            // file: [0; 128],
            ops: DHCPOps {
                typ: DHCPOpsTyp::Request,
                pars: vec![
                    DHCPParameter::AddressRequested(offer.yiaddr),
                    DHCPParameter::Server(offer.siaddr),
                ],
            },
        }
    }

    pub fn ack(request: DHCPMessage, ops_response: Vec<DHCPParameter>) -> DHCPMessage {
        DHCPMessage {
            op: DHCPOp::BootReply,
            htype: 0x01,
            hlen: 0x06,
            hops: 0x00,
            xid: request.xid,
            secs: 0x0000,
            flags: 0x0000,
            ciaddr: Ipv4Addr::UNSPECIFIED,
            yiaddr: request.ciaddr,
            siaddr: request.siaddr,
            giaddr: Ipv4Addr::UNSPECIFIED,
            chaddr: request.chaddr,
            // sname: [0; 64],
            // file: [0; 128],
            ops: DHCPOps {
                typ: DHCPOpsTyp::Ack,
                pars: ops_response,
            },
        }
    }
}

impl DHCPMessage {
    pub fn into_bytestream(&self) -> Result<Vec<u8>, std::io::Error> {
        let mut res = Vec::with_capacity(256);
        (self.op as u8).write_to(&mut res, BigEndian)?;

        self.htype.write_to(&mut res, BigEndian)?;
        self.hlen.write_to(&mut res, BigEndian)?;
        self.hops.write_to(&mut res, BigEndian)?;

        self.xid.write_to(&mut res, BigEndian)?;

        self.secs.write_to(&mut res, BigEndian)?;
        self.flags.write_to(&mut res, BigEndian)?;

        u32::from_be_bytes(self.ciaddr.octets()).write_to(&mut res, BigEndian)?;
        u32::from_be_bytes(self.yiaddr.octets()).write_to(&mut res, BigEndian)?;
        u32::from_be_bytes(self.siaddr.octets()).write_to(&mut res, BigEndian)?;
        u32::from_be_bytes(self.giaddr.octets()).write_to(&mut res, BigEndian)?;

        // 2 byte padding
        res.extend([0u8, 0u8]);
        self.chaddr.to_bytestream(&mut res)?;

        // op
        (self.ops.typ as u8).write_to(&mut res, BigEndian)?;
        for p in &self.ops.pars {
            p.append_to_bytestream(&mut res)?
        }

        Ok(res)
    }
}

impl DHCPParameter {
    fn append_to_bytestream(&self, w: &mut Vec<u8>) -> std::io::Result<()> {
        match self {
            Self::ReqSubnetMask => 0x10u8.write_to(w, BigEndian)?,
            Self::SubnetMask(ip) => {
                0x11u8.write_to(w, BigEndian)?;
                u32::from_be_bytes(ip.octets()).write_to(w, BigEndian)?;
            }

            Self::ReqRouter => 0x20u8.write_to(w, BigEndian)?,
            Self::Router(ip) => {
                0x21u8.write_to(w, BigEndian)?;
                u32::from_be_bytes(ip.octets()).write_to(w, BigEndian)?;
            }

            Self::ReqDomainName => 0x30u8.write_to(w, BigEndian)?,
            Self::DomainName() => 0x31u8.write_to(w, BigEndian)?,

            Self::ReqDomainNameServer => 0x40u8.write_to(w, BigEndian)?,
            Self::DomainNameServer(ip) => {
                0x41u8.write_to(w, BigEndian)?;
                u32::from_be_bytes(ip.octets()).write_to(w, BigEndian)?;
            }

            Self::AddressRequested(ip) => {
                0x50u8.write_to(w, BigEndian)?;
                u32::from_be_bytes(ip.octets()).write_to(w, BigEndian)?;
            }

            Self::Server(ip) => {
                0x60u8.write_to(w, BigEndian)?;
                u32::from_be_bytes(ip.octets()).write_to(w, BigEndian)?;
            }
        }
        Ok(())
    }
}

impl MessageBody for DHCPMessage {
    fn byte_len(&self) -> usize {
        40
    }
}

impl TryFrom<&[u8]> for DHCPMessage {
    type Error = std::io::Error;
    fn try_from(ptr: &[u8]) -> Result<Self, Self::Error> {
        let mut ptr = Cursor::new(ptr);

        let op = u8::read_from(&mut ptr, BigEndian)?;
        let op = match op {
            1 => DHCPOp::BootRequest,
            2 => DHCPOp::BootReply,
            3 => DHCPOp::Wakeup,
            _ => unimplemented!(),
        };

        let htype = u8::read_from(&mut ptr, BigEndian)?;
        let hlen = u8::read_from(&mut ptr, BigEndian)?;
        let hops = u8::read_from(&mut ptr, BigEndian)?;

        let xid = u32::read_from(&mut ptr, BigEndian)?;

        let secs = u16::read_from(&mut ptr, BigEndian)?;
        let flags = u16::read_from(&mut ptr, BigEndian)?;

        let ciaddr = Ipv4Addr::from(u32::read_from(&mut ptr, BigEndian)?);
        let yiaddr = Ipv4Addr::from(u32::read_from(&mut ptr, BigEndian)?);
        let siaddr = Ipv4Addr::from(u32::read_from(&mut ptr, BigEndian)?);
        let giaddr = Ipv4Addr::from(u32::read_from(&mut ptr, BigEndian)?);

        assert_eq!(u16::read_from(&mut ptr, BigEndian)?, 0);
        let chaddr = MacAddress::from_bytestream(&mut ptr)?;

        let pos = ptr.position() as usize;
        let stream = ptr.into_inner();
        let ops = DHCPOps::try_from(&stream[pos..])?;

        Ok(Self {
            op,
            htype,
            hlen,
            hops,
            xid,
            secs,
            flags,
            ciaddr,
            yiaddr,
            siaddr,
            giaddr,
            chaddr,
            ops,
        })
    }
}

impl TryFrom<&[u8]> for DHCPOps {
    type Error = std::io::Error;
    fn try_from(ptr: &[u8]) -> Result<Self, Self::Error> {
        let mut ptr = Cursor::new(ptr);
        let typ = u8::read_from(&mut ptr, BigEndian)?;
        let typ = match typ {
            1 => DHCPOpsTyp::Discover,
            2 => DHCPOpsTyp::Offer,
            3 => DHCPOpsTyp::Request,
            4 => DHCPOpsTyp::Ack,
            _ => unimplemented!(),
        };

        let mut pars = Vec::new();
        while let Ok(tag) = u8::read_from(&mut ptr, BigEndian) {
            match tag {
                0x10 => pars.push(DHCPParameter::ReqSubnetMask),
                0x11 => pars.push(DHCPParameter::SubnetMask(Ipv4Addr::from(u32::read_from(
                    &mut ptr, BigEndian,
                )?))),

                0x20 => pars.push(DHCPParameter::ReqRouter),
                0x21 => pars.push(DHCPParameter::Router(Ipv4Addr::from(u32::read_from(
                    &mut ptr, BigEndian,
                )?))),

                0x30 => pars.push(DHCPParameter::ReqDomainName),
                0x31 => pars.push(DHCPParameter::DomainName()),

                0x40 => pars.push(DHCPParameter::ReqDomainNameServer),
                0x41 => pars.push(DHCPParameter::DomainNameServer(Ipv4Addr::from(
                    u32::read_from(&mut ptr, BigEndian)?,
                ))),

                0x50 => pars.push(DHCPParameter::AddressRequested(Ipv4Addr::from(
                    u32::read_from(&mut ptr, BigEndian)?,
                ))),

                0x60 => pars.push(DHCPParameter::Server(Ipv4Addr::from(u32::read_from(
                    &mut ptr, BigEndian,
                )?))),

                _ => unimplemented!(),
            }
        }

        Ok(Self { typ, pars })
    }
}
