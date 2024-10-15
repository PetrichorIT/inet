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
pub struct IcmpV4Packet {
    pub typ: IcmpV4Type,  // icmp info
    pub content: Vec<u8>, // ip header + first 8 byte payload or padding
}

const PAYLOAD_LIMIT: usize = 20 + 64;

impl IcmpV4Packet {
    pub fn new(typ: IcmpV4Type, pkt: &Ipv4Packet) -> Self {
        let mut content = pkt.to_vec().expect("Failed to write incoming IP ???");
        dbg!(content.len());
        content.truncate(PAYLOAD_LIMIT);
        Self { typ, content }
    }

    pub fn contained(&self) -> Result<Ipv4Packet, Error> {
        // Override len with 8
        let mut buffer = self.content.clone();
        let len = buffer.len().min(PAYLOAD_LIMIT);
        assert!(len < 256);
        buffer[2] = 0;
        buffer[3] = len as u8;
        Ipv4Packet::read_from_slice(&mut &buffer[..])
    }
}

impl ToBytestream for IcmpV4Packet {
    type Error = Error;
    fn to_bytestream(&self, bytestream: &mut BytestreamWriter) -> Result<(), Self::Error> {
        self.typ.to_bytestream(bytestream)?;
        bytestream.write_all(&self.content)
    }
}

impl FromBytestream for IcmpV4Packet {
    type Error = Error;
    fn from_bytestream(bytestream: &mut BytestreamReader) -> Result<Self, Self::Error> {
        let typ = IcmpV4Type::from_bytestream(bytestream)?;
        let mut content = vec![0; PAYLOAD_LIMIT];
        let n = bytestream.read(&mut content)?;
        content.truncate(n);
        Ok(Self { typ, content })
    }
}

// # Types

pub const PROTO_ICMPV4: u8 = 1;

/// The type of the ICMP control message
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum IcmpV4Type {
    EchoReply {
        identifier: u16,
        sequence: u16,
    } = 0,
    DestinationUnreachable {
        next_hop_mtu: u16,
        code: IcmpV4DestinationUnreachableCode,
    } = 3,
    SourceQuench = 4,
    RedirectMessage {
        addr: Ipv4Addr,
        code: IcmpV4RedirectCode,
    } = 5,
    EchoRequest {
        identifier: u16,
        sequence: u16,
    } = 8,
    RouterAdvertisment = 9,
    RouterSolicitation = 10,
    TimeExceeded {
        code: IcmpV4TimeExceededCode,
    } = 11,
    BadIpHeader {
        code: IcmpV4BadIpHeaderCode,
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

impl ToBytestream for IcmpV4Type {
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

impl FromBytestream for IcmpV4Type {
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
                    code: IcmpV4DestinationUnreachableCode::from_raw_repr(code)?,
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
                    code: IcmpV4RedirectCode::from_raw_repr(code)?,
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
                    code: IcmpV4TimeExceededCode::from_raw_repr(code)?,
                })
            }
            12 => {
                let _ = stream.read_u32::<BE>()?;
                Ok(Self::BadIpHeader {
                    code: IcmpV4BadIpHeaderCode::from_raw_repr(code)?,
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
    pub enum IcmpV4RedirectCode {
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
    pub enum IcmpV4TimeExceededCode {
        type Repr = u8 where BigEndian;
        TimeToLifeInTransit = 0,
        FragmentReassemblyTimeExceeded = 1,
    }
}

raw_enum! {
    /// A reponse code to a ICMP desintation unreachable message.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub enum IcmpV4DestinationUnreachableCode {
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
    pub enum IcmpV4BadIpHeaderCode {
        type Repr = u8 where BigEndian;
        SeePointer = 0,
        MissingRequiredOption = 1,
        BadLength = 2,
    }
}
