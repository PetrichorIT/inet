use std::{io, time::Duration};

use bitflags::bitflags;
use bytes_io::{BE, BytesReader, BytesWriter, FromBytes, ReadBytesExt, ToBytes, WriteBytesExt};

mod ipv6;
mod lsa;

pub use self::ipv6::*;
pub use self::lsa::*;

pub const PROTO_OSPF: u8 = 89;
pub const OSPF_VERSION: u8 = 3;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OspfPacket {
    // version: u8,
    // typ: u8
    pub router_id: RouterId,
    pub area_id: AreaId,
    pub instance_id: u8,
    pub content: OspfPacketType,
}

type RouterId = u32;
type AreaId = u32;

const KIND_HELLO: u8 = 1;
const KIND_DATABASE_DESCRIPTION: u8 = 2;
const KIND_LINK_STATE_REQUEST: u8 = 3;
const KIND_LINK_STATE_UPDATE: u8 = 4;
const KIND_LINK_STATE_ACK: u8 = 5;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OspfPacketType {
    Hello(OspfHelloPacket),
    DatabaseDescription(OspfDatabaseDescriptionPacket),
    LinkStateRequest(OspfLinkStateRequestPacket),
    LinkStateUpdate(OspfLinkStateUpdatePacket),
    LinkStateAck(OspfLinkStateAckPacket),
}

impl OspfPacketType {
    fn typ(&self) -> u8 {
        match self {
            OspfPacketType::Hello(_) => KIND_HELLO,
            OspfPacketType::DatabaseDescription(_) => KIND_DATABASE_DESCRIPTION,
            OspfPacketType::LinkStateRequest(_) => KIND_LINK_STATE_REQUEST,
            OspfPacketType::LinkStateUpdate(_) => KIND_LINK_STATE_UPDATE,
            OspfPacketType::LinkStateAck(_) => KIND_LINK_STATE_ACK,
        }
    }
}

impl ToBytes for OspfPacket {
    type Error = io::Error;
    fn to_bytes(&self, writer: &mut BytesWriter) -> Result<(), Self::Error> {
        writer.write_u8(OSPF_VERSION)?;
        writer.write_u8(self.content.typ() as u8)?;
        let marker = writer.marker::<u16>();
        writer.write_u32::<BE>(self.router_id)?;
        writer.write_u32::<BE>(self.area_id)?;
        writer.write_u16::<BE>(0)?; // checksum
        writer.write_u8(self.instance_id)?;
        writer.write_u8(0)?; // reserved

        match self.content {
            OspfPacketType::Hello(ref packet) => packet.to_bytes(writer)?,
            OspfPacketType::DatabaseDescription(ref packet) => packet.to_bytes(writer)?,
            OspfPacketType::LinkStateRequest(ref packet) => packet.to_bytes(writer)?,
            OspfPacketType::LinkStateUpdate(ref packet) => packet.to_bytes(writer)?,
            OspfPacketType::LinkStateAck(ref packet) => packet.to_bytes(writer)?,
        };

        let len = writer.bytes_written_since(&marker) + 4;
        writer.apply(marker).write_u16::<BE>(len as u16)?;

        Ok(())
    }
}

impl FromBytes for OspfPacket {
    type Error = io::Error;
    fn from_bytes(stream: &mut BytesReader) -> Result<Self, Self::Error> {
        let version = stream.read_u8()?;
        let typ = stream.read_u8()?;
        let len = stream.read_u16::<BE>()? as usize - 16;

        let router_id = stream.read_u32::<BE>()?;
        let area_id = stream.read_u32::<BE>()?;

        let _ = stream.read_u16::<BE>()?;
        let instance_id = stream.read_u8()?;
        let _ = stream.read_u8()?;

        let content = stream.extract(len, |body| match typ {
            KIND_HELLO => Ok(OspfPacketType::Hello(OspfHelloPacket::from_bytes(body)?)),
            KIND_DATABASE_DESCRIPTION => Ok(OspfPacketType::DatabaseDescription(
                OspfDatabaseDescriptionPacket::from_bytes(body)?,
            )),
            KIND_LINK_STATE_REQUEST => Ok(OspfPacketType::LinkStateRequest(
                OspfLinkStateRequestPacket::from_bytes(body)?,
            )),
            KIND_LINK_STATE_UPDATE => Ok(OspfPacketType::LinkStateUpdate(
                OspfLinkStateUpdatePacket::from_bytes(body)?,
            )),
            KIND_LINK_STATE_ACK => Ok(OspfPacketType::LinkStateAck(
                OspfLinkStateAckPacket::from_bytes(body)?,
            )),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unknown packet type",
            )),
        })?;

        assert_eq!(version, OSPF_VERSION);

        Ok(Self {
            router_id,
            area_id,
            instance_id,
            content,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OspfHelloPacket {
    pub interface_id: u32,
    pub hello_interval: Duration,
    pub options: OspfOptions,
    pub router_priority: u8,
    pub router_dead_interval: Duration,
    pub designated_router_id: RouterId,
    pub backup_router_id: RouterId,
    pub neighbor_ids: Vec<RouterId>,
}

impl ToBytes for OspfHelloPacket {
    type Error = io::Error;
    fn to_bytes(&self, writer: &mut BytesWriter) -> Result<(), Self::Error> {
        writer.write_u32::<BE>(self.interface_id)?;

        let dword = ((self.router_priority as u32) << 24) | (self.options.bits() & 0x00_ff_ff_ff);
        writer.write_u32::<BE>(dword)?;

        writer.write_u16::<BE>(self.hello_interval.as_secs() as u16)?;
        writer.write_u16::<BE>(self.router_dead_interval.as_secs() as u16)?;

        writer.write_u32::<BE>(self.designated_router_id)?;
        writer.write_u32::<BE>(self.backup_router_id)?;

        for id in &self.neighbor_ids {
            writer.write_u32::<BE>(*id)?;
        }
        Ok(())
    }
}

impl FromBytes for OspfHelloPacket {
    type Error = io::Error;
    fn from_bytes(stream: &mut BytesReader) -> Result<Self, Self::Error> {
        let interface_id = stream.read_u32::<BE>()?;
        let dword = stream.read_u32::<BE>()?;
        let hello_interval = stream.read_u16::<BE>()?;
        let router_dead_interval = Duration::from_secs(stream.read_u16::<BE>()? as u64);
        let designated_router_id = stream.read_u32::<BE>()?;
        let backup_router_id = stream.read_u32::<BE>()?;
        let mut neighbor_ids = Vec::new();
        while stream.has_remaining() {
            neighbor_ids.push(stream.read_u32::<BE>()?);
        }

        let router_priority = u8::try_from((dword & 0xff_00_00_00) >> 24).expect("cannot fail");
        let options = OspfOptions::from_bits_truncate(dword);

        Ok(Self {
            interface_id,
            hello_interval: Duration::from_secs(hello_interval as u64),
            options,
            router_priority,
            router_dead_interval,
            designated_router_id,
            backup_router_id,
            neighbor_ids,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OspfDatabaseDescriptionPacket {
    pub interface_mtu: u16,
    pub options: OspfOptions,
    pub db_options: OspfDatabaseDescriptionOptions,
    pub dd_sequence_number: u32,
    pub lsas: Vec<LsaOnlyHeader>,
}

bitflags! {
    pub struct OspfDatabaseDescriptionOptions: u16 {
        const MASTER_SLAVE  = 0b0000_0001;
        const MORE          = 0b0000_0010;
        const INIT          = 0b0000_0100;
    }
}

impl ToBytes for OspfDatabaseDescriptionPacket {
    type Error = io::Error;
    fn to_bytes(&self, writer: &mut BytesWriter) -> Result<(), Self::Error> {
        writer.write_u32::<BE>(self.options.bits())?;
        writer.write_u16::<BE>(self.interface_mtu)?;
        writer.write_u16::<BE>(self.db_options.bits())?;
        writer.write_u32::<BE>(self.dd_sequence_number)?;
        for lsa in &self.lsas {
            lsa.to_bytes(writer)?;
        }

        Ok(())
    }
}

impl FromBytes for OspfDatabaseDescriptionPacket {
    type Error = io::Error;
    fn from_bytes(stream: &mut BytesReader) -> Result<Self, Self::Error> {
        let options = OspfOptions::from_bits_truncate(stream.read_u32::<BE>()?);
        let interface_mtu = stream.read_u16::<BE>()?;
        let db_options =
            OspfDatabaseDescriptionOptions::from_bits_truncate(stream.read_u16::<BE>()?);
        let dd_sequence_number = stream.read_u32::<BE>()?;

        let mut lsas = Vec::new();
        while stream.has_remaining() {
            lsas.push(LsaOnlyHeader::from_bytes(stream)?);
        }
        Ok(OspfDatabaseDescriptionPacket {
            interface_mtu,
            options,
            db_options,
            dd_sequence_number,
            lsas,
        })
    }
}

bitflags! {
    pub struct OspfOptions: u32 {
        const EXTERNAL              = 0b0000_0010;
        const MULTICAST             = 0b0000_0100;
        // const NP                    = 0b0000_1000;
        // const EXTERNAL_ATTRIBUTES   = 0b0001_0000;
        const DEMAND_CIRCUITS       = 0b0010_0000;
    }
}

// this shoudl be a vec
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OspfLinkStateRequestPacket {
    pub ls_typ: u16,
    pub link_state_id: u32,
    pub advertising_router: RouterId,
}

impl ToBytes for OspfLinkStateRequestPacket {
    type Error = io::Error;
    fn to_bytes(&self, writer: &mut BytesWriter) -> Result<(), Self::Error> {
        writer.write_u32::<BE>(self.ls_typ as u32)?;
        writer.write_u32::<BE>(self.link_state_id)?;
        writer.write_u32::<BE>(self.advertising_router)?;
        Ok(())
    }
}

impl FromBytes for OspfLinkStateRequestPacket {
    type Error = io::Error;
    fn from_bytes(stream: &mut BytesReader) -> Result<Self, Self::Error> {
        println!("- link state: {:?}", stream.chunk());

        let ls_typ = u16::try_from(stream.read_u32::<BE>()? & 0xff_ff).expect("cannot fail");
        let link_state_id = stream.read_u32::<BE>()?;
        let advertising_router = stream.read_u32::<BE>()?;
        Ok(OspfLinkStateRequestPacket {
            ls_typ,
            link_state_id,
            advertising_router,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OspfLinkStateUpdatePacket {
    pub lsas: Vec<Lsa>,
}

impl ToBytes for OspfLinkStateUpdatePacket {
    type Error = io::Error;
    fn to_bytes(&self, writer: &mut BytesWriter) -> Result<(), Self::Error> {
        writer.write_u32::<BE>(self.lsas.len() as u32)?;
        for lsa in &self.lsas {
            lsa.to_bytes(writer)?;
        }
        Ok(())
    }
}

impl FromBytes for OspfLinkStateUpdatePacket {
    type Error = io::Error;
    fn from_bytes(reader: &mut BytesReader) -> Result<Self, Self::Error> {
        let num_lsas = reader.read_u32::<BE>()?;
        let mut lsas = Vec::with_capacity(num_lsas as usize);
        for _ in 0..num_lsas {
            lsas.push(Lsa::from_bytes(reader)?);
        }
        Ok(OspfLinkStateUpdatePacket { lsas })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OspfLinkStateAckPacket {
    pub lsas: Vec<LsaOnlyHeader>, // with LsaKind::NoContent
}

impl ToBytes for OspfLinkStateAckPacket {
    type Error = io::Error;
    fn to_bytes(&self, writer: &mut BytesWriter) -> Result<(), Self::Error> {
        for lsa in &self.lsas {
            lsa.to_bytes(writer)?;
        }
        Ok(())
    }
}

impl FromBytes for OspfLinkStateAckPacket {
    type Error = io::Error;
    fn from_bytes(reader: &mut BytesReader) -> Result<Self, Self::Error> {
        let mut lsas = Vec::new();
        while reader.has_remaining() {
            lsas.push(LsaOnlyHeader::from_bytes(reader)?);
        }
        Ok(Self { lsas })
    }
}

#[cfg(test)]
mod test {
    use bytes_io::assert_encoding_e2e;
    use rand::{Rng, rng};

    use super::*;

    impl OspfPacket {
        pub fn random() -> Self {
            OspfPacket {
                router_id: rng().random(),
                area_id: rng().random(),
                instance_id: rng().random(),
                content: match 1 + (rng().random::<u8>() % 5) {
                    KIND_HELLO => OspfPacketType::Hello(OspfHelloPacket::random()),
                    KIND_DATABASE_DESCRIPTION => {
                        OspfPacketType::DatabaseDescription(OspfDatabaseDescriptionPacket::random())
                    }
                    KIND_LINK_STATE_REQUEST => {
                        OspfPacketType::LinkStateRequest(OspfLinkStateRequestPacket::random())
                    }
                    KIND_LINK_STATE_UPDATE => {
                        OspfPacketType::LinkStateUpdate(OspfLinkStateUpdatePacket::random())
                    }
                    KIND_LINK_STATE_ACK => {
                        OspfPacketType::LinkStateAck(OspfLinkStateAckPacket::random())
                    }
                    _ => unreachable!(),
                },
            }
        }
    }

    #[test]
    fn e2e_encoding() {
        let fuzzed = std::iter::repeat_with(OspfPacket::random)
            .take(100)
            .collect::<Vec<_>>();
        assert_encoding_e2e(&fuzzed);
    }
    impl OspfHelloPacket {
        fn random() -> Self {
            OspfHelloPacket {
                interface_id: rng().random::<u32>(),
                hello_interval: Duration::from_secs(rng().random::<u64>() % 200),
                options: OspfOptions::from_bits_truncate(rng().random()),
                router_dead_interval: Duration::from_secs(rng().random::<u64>() % 200),
                router_priority: rng().random(),
                designated_router_id: rng().random(),
                backup_router_id: rng().random(),
                neighbor_ids: std::iter::repeat_with(|| rng().random())
                    .take((rng().random::<u8>() % 10) as usize)
                    .collect(),
            }
        }
    }

    #[test]
    fn e2e_encoding_hello_packet() {
        let fuzzed = std::iter::repeat_with(OspfHelloPacket::random)
            .take(100)
            .collect::<Vec<_>>();
        assert_encoding_e2e(&fuzzed);
    }

    impl OspfDatabaseDescriptionPacket {
        fn random() -> Self {
            OspfDatabaseDescriptionPacket {
                interface_mtu: rng().random(),
                options: OspfOptions::from_bits_truncate(rng().random()),
                db_options: OspfDatabaseDescriptionOptions::from_bits_truncate(rng().random()),
                dd_sequence_number: rng().random(),
                lsas: std::iter::repeat_with(LsaOnlyHeader::random)
                    .take((rng().random::<u8>() % 3) as usize + 1)
                    .collect(),
            }
        }
    }

    #[test]
    fn e2e_encoding_database_packet() {
        let fuzzed = std::iter::repeat_with(OspfDatabaseDescriptionPacket::random)
            .take(100)
            .collect::<Vec<_>>();
        assert_encoding_e2e(&fuzzed);
    }

    impl OspfLinkStateRequestPacket {
        fn random() -> Self {
            OspfLinkStateRequestPacket {
                ls_typ: rng().random::<u16>() % 6,
                link_state_id: rng().random(),
                advertising_router: rng().random(),
            }
        }
    }

    #[test]
    fn e2e_encoding_link_state_request_packet() {
        let fuzzed = std::iter::repeat_with(OspfLinkStateRequestPacket::random)
            .take(100)
            .collect::<Vec<_>>();
        assert_encoding_e2e(&fuzzed);
    }

    impl OspfLinkStateUpdatePacket {
        fn random() -> Self {
            OspfLinkStateUpdatePacket {
                lsas: std::iter::repeat_with(Lsa::random)
                    .take((rng().random::<u8>() % 5) as usize + 1)
                    .collect(),
            }
        }
    }

    #[test]
    fn e2e_encoding_link_state_update_packet() {
        let fuzzed = std::iter::repeat_with(OspfLinkStateUpdatePacket::random)
            .take(100)
            .collect::<Vec<_>>();
        assert_encoding_e2e(&fuzzed);
    }

    impl OspfLinkStateAckPacket {
        fn random() -> Self {
            OspfLinkStateAckPacket {
                lsas: std::iter::repeat_with(LsaOnlyHeader::random)
                    .take((rng().random::<u8>() % 5) as usize + 1)
                    .collect(),
            }
        }
    }

    #[test]
    fn e2e_encoding_link_state_ack_packet() {
        let fuzzed = std::iter::repeat_with(OspfLinkStateAckPacket::random)
            .take(100)
            .collect::<Vec<_>>();
        assert_encoding_e2e(&fuzzed);
    }
}
