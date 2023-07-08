use std::{
    io::{Error, Read, Write},
    net::Ipv4Addr,
};

use bytepack::{
    raw_enum, BytestreamReader, BytestreamWriter, FromBytestream, ReadBytesExt, ToBytestream,
    WriteBytesExt, BE,
};

use crate::ip::Ipv4Packet;

/// An ICMP packet
#[derive(Debug)]
pub struct IcmpPacket {
    pub typ: IcmpType,    // icmp info
    pub content: Vec<u8>, // ip header + first 8 byte payload or padding
}

impl IcmpPacket {
    pub fn new(typ: IcmpType, pkt: &Ipv4Packet) -> Self {
        let mut content = pkt.to_vec().expect("Failed to write incoming IP ???");
        content.truncate(28);
        Self { typ, content }
    }

    pub fn contained(&mut self) -> Ipv4Packet {
        // Override len with 8
        self.content[2] = 0;
        self.content[3] = 20 + 8;
        let ip = Ipv4Packet::read_from_slice(&mut &self.content[..]).unwrap();
        ip
    }
}

impl ToBytestream for IcmpPacket {
    type Error = Error;
    fn to_bytestream(&self, bytestream: &mut BytestreamWriter) -> Result<(), Self::Error> {
        self.typ.to_bytestream(bytestream)?;
        bytestream.write_all(&self.content)
    }
}

impl FromBytestream for IcmpPacket {
    type Error = Error;
    fn from_bytestream(bytestream: &mut BytestreamReader) -> Result<Self, Self::Error> {
        let typ = IcmpType::from_bytestream(bytestream)?;
        let mut content = vec![0; 20 + 8];
        let n = bytestream.read(&mut content)?;
        content.truncate(n);
        Ok(Self { typ, content })
    }
}

// # Types

pub const PROTO_ICMP: u8 = 1;

/// The type of the ICMP control message
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum IcmpType {
    EchoReply {
        identifier: u16,
        sequence: u16,
    } = 0,
    DestinationUnreachable {
        next_hop_mtu: u16,
        code: IcmpDestinationUnreachableCode,
    } = 3,
    SourceQuench = 4,
    RedirectMessage {
        addr: Ipv4Addr,
        code: IcmpRedirectCode,
    } = 5,
    EchoRequest {
        identifier: u16,
        sequence: u16,
    } = 8,
    RouterAdvertisment = 9,
    RouterSolicitation = 10,
    TimeExceeded {
        code: IcmpTimeExceededCode,
    } = 11,
    BadIpHeader {
        code: IcmpBadIpHeaderCode,
    } = 12,
    Timestamp {
        identifier: u16,
        sequence: u16,
        ts_org: u32,
        ts_rcv: u32,
        ts_transmit: u32,
    } = 13,
    TimestmapReply {
        identifier: u16,
        sequence: u16,
        ts_org: u32,
        ts_rcv: u32,
        ts_transmit: u32,
    } = 14,
    #[deprecated]
    InformationRequest = 15,
    #[deprecated]
    InformationReply = 16,
    #[deprecated]
    AddressMaskRequest = 17,
    #[deprecated]
    AddressMaskReply = 18,
    ExtendedEchoRequest = 42,
    ExtendedEchoReply = 43,
}

impl ToBytestream for IcmpType {
    type Error = Error;
    fn to_bytestream(&self, stream: &mut BytestreamWriter) -> Result<(), Self::Error> {
        match self {
            Self::EchoReply {
                identifier,
                sequence,
            } => {
                stream.write_u8(0)?;
                stream.write_u8(0)?;
                stream.write_u16::<BE>(0)?;
                stream.write_u16::<BE>(*identifier)?;
                stream.write_u16::<BE>(*sequence)?;
                Ok(())
            }
            Self::DestinationUnreachable { next_hop_mtu, code } => {
                stream.write_u8(3)?;
                stream.write_u8(code.to_raw_repr())?;
                stream.write_u16::<BE>(0)?; // checksum
                stream.write_u16::<BE>(0)?; // unused
                stream.write_u16::<BE>(*next_hop_mtu)?;
                Ok(())
            }
            Self::SourceQuench => {
                stream.write_u8(4)?;
                stream.write_u8(0)?;
                stream.write_u16::<BE>(0)?; // checksum
                stream.write_u32::<BE>(0)?; // unused
                Ok(())
            }
            Self::RedirectMessage { addr, code } => {
                stream.write_u8(5)?;
                stream.write_u8(code.to_raw_repr())?;
                stream.write_u16::<BE>(0)?; // checksum
                stream.write_all(&addr.octets())?;
                Ok(())
            }
            Self::EchoRequest {
                identifier,
                sequence,
            } => {
                stream.write_u8(8)?;
                stream.write_u8(0)?;
                stream.write_u16::<BE>(0)?; // checksum
                stream.write_u16::<BE>(*identifier)?;
                stream.write_u16::<BE>(*sequence)?;
                Ok(())
            }
            Self::RouterAdvertisment => {
                stream.write_u8(9)?;
                stream.write_u8(0)?;
                stream.write_u16::<BE>(0)?; // checksum
                stream.write_u32::<BE>(0)?;
                Ok(())
            }
            Self::RouterSolicitation => {
                stream.write_u8(10)?;
                stream.write_u8(0)?;
                stream.write_u16::<BE>(0)?; // checksum
                stream.write_u32::<BE>(0)?;
                Ok(())
            }
            Self::TimeExceeded { code } => {
                stream.write_u8(11)?;
                stream.write_u8(code.to_raw_repr())?;
                stream.write_u16::<BE>(0)?; // checksum
                stream.write_u32::<BE>(0)?;
                Ok(())
            }
            Self::BadIpHeader { code } => {
                stream.write_u8(12)?;
                stream.write_u8(code.to_raw_repr())?;
                stream.write_u16::<BE>(0)?; // checksum
                stream.write_u32::<BE>(0)?;
                Ok(())
            }
            _ => todo!(),
        }
    }
}

impl FromBytestream for IcmpType {
    type Error = Error;
    fn from_bytestream(stream: &mut BytestreamReader) -> Result<Self, Self::Error> {
        let typ = stream.read_u8()?;
        let code = stream.read_u8()?;
        let _checksum = stream.read_u16::<BE>()?;

        match typ {
            0 => {
                assert_eq!(code, 0, "Divergent code not allowed on echo reply");
                let identifier = stream.read_u16::<BE>()?;
                let sequence = stream.read_u16::<BE>()?;
                Ok(Self::EchoReply {
                    identifier,
                    sequence,
                })
            }
            3 => {
                let _ = stream.read_u16::<BE>()?;
                let next_hop_mtu = stream.read_u16::<BE>()?;
                Ok(Self::DestinationUnreachable {
                    next_hop_mtu: next_hop_mtu,
                    code: IcmpDestinationUnreachableCode::from_raw_repr(code)?,
                })
            }
            4 => {
                assert_eq!(code, 0, "Divergent code not allowed on source quench");
                let _ = stream.read_u32::<BE>()?;
                Ok(Self::SourceQuench)
            }
            5 => {
                let addr = Ipv4Addr::from(stream.read_u32::<BE>()?);

                Ok(Self::RedirectMessage {
                    addr,
                    code: IcmpRedirectCode::from_raw_repr(code)?,
                })
            }
            8 => {
                assert_eq!(code, 0, "Divergent code not allowed on echo request");
                let identifier = stream.read_u16::<BE>()?;
                let sequence = stream.read_u16::<BE>()?;
                Ok(Self::EchoRequest {
                    identifier,
                    sequence,
                })
            }
            9 => {
                assert_eq!(code, 0, "Divergent code not allowed on route advertisment");
                let _ = stream.read_u32::<BE>()?;
                Ok(Self::RouterAdvertisment)
            }
            10 => {
                assert_eq!(code, 0, "Divergent code not allowed on route solicitation");
                let _ = stream.read_u32::<BE>()?;
                Ok(Self::RouterSolicitation)
            }
            11 => {
                let _ = stream.read_u32::<BE>()?;
                Ok(Self::TimeExceeded {
                    code: IcmpTimeExceededCode::from_raw_repr(code)?,
                })
            }
            12 => {
                let _ = stream.read_u32::<BE>()?;
                Ok(Self::BadIpHeader {
                    code: IcmpBadIpHeaderCode::from_raw_repr(code)?,
                })
            }
            _ => todo!(),
        }
    }
}

// # Codes

raw_enum! {
     /// A reponse code to a ICMP redirect message.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub enum IcmpRedirectCode {
        type Repr = u8 where BigEndian;
        RedirectForNetwork = 0,
        RedirectForHost = 1,
        RedirectForTypeOfServiceAndNetwork = 2,
        RedirectForTypeOfServiceAndHost = 3,
    }
}

raw_enum! {
     /// A reponse code to a ICMP time exceeded message.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub enum IcmpTimeExceededCode {
        type Repr = u8 where BigEndian;
        TimeToLifeInTransit = 0,
        FragmentReassemblyTimeExceeded = 1,
    }
}

raw_enum! {
    /// A reponse code to a ICMP desintation unreachable message.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub enum IcmpDestinationUnreachableCode {
        type Repr = u8 where BigEndian;
        NetworkUnreachable = 0,
        HostUnreachable = 1,
        ProtocolUnreachable = 2,
        PortUnreachable = 3,
        DatagramToBig = 4,
        SourceRouteFailed = 5,
        DestinationNetworkFailed = 6,
        DestionationHostFailed = 7,
        SourceHostFailed = 8,
        DestinationNetworkProhibited = 9,
        DestinationHostProhibited = 10,
        NetworkUnreachableForTOS = 11,
        HostUnreachableForTOS = 12,
        CommunicationProhibited = 13,
        HostPrecedenceViolation = 14,
        PrecedenceCutoff = 15,
    }
}

raw_enum! {
     /// A reponse code to a ICMP desintation unreachable message.
     #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub enum IcmpBadIpHeaderCode {
        type Repr = u8 where BigEndian;
        SeePointer = 0,
        MissingRequiredOption = 1,
        BadLength = 2,
    }
}
