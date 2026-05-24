use std::{
    io::{self, Write},
    net::Ipv6Addr,
    ops::{Deref, DerefMut},
    time::Duration,
};

use bitflags::bitflags;
use bytes_io::{BE, BytesReader, BytesWriter, FromBytes, ReadBytesExt, ToBytes, WriteBytesExt};
use macros::repr_enum;

use super::{Ipv6Prefix, OspfOptions, RouterId};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lsa {
    pub header: LsaHeader,
    pub content: LsaKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LsaHeader {
    pub ls_age: Duration,
    pub link_state_id: u32,
    pub advertising_router: u32,
    pub ls_seq_no: u32,
    pub flags: LasTypeFlags,
}

impl Lsa {
    fn typ(&self) -> LsaType {
        LsaType {
            flags: self.flags,
            code: self.content.typ(),
        }
    }
}

impl Deref for Lsa {
    type Target = LsaHeader;
    fn deref(&self) -> &Self::Target {
        &self.header
    }
}

impl DerefMut for Lsa {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.header
    }
}

impl ToBytes for Lsa {
    type Error = io::Error;

    fn to_bytes(&self, writer: &mut BytesWriter) -> Result<(), Self::Error> {
        writer.write_u16::<BE>(self.ls_age.as_secs() as u16)?;
        self.typ().to_bytes(writer)?;

        writer.write_u32::<BE>(self.link_state_id)?;
        writer.write_u32::<BE>(self.advertising_router)?;
        writer.write_u32::<BE>(self.ls_seq_no)?;

        writer.write_u16::<BE>(0)?; // checksum
        let marker = writer.marker::<u16>();

        match self.content {
            LsaKind::RouterLsa(ref lsa) => lsa.to_bytes(writer)?,
            LsaKind::NetworkLsa(ref lsa) => lsa.to_bytes(writer)?,
            LsaKind::InterAreaPrefixLsa(ref lsa) => lsa.to_bytes(writer)?,
            LsaKind::InterAreaRouterLsa(ref lsa) => lsa.to_bytes(writer)?,
            LsaKind::AsExternalLsa(ref lsa) => lsa.to_bytes(writer)?,
            LsaKind::LinkLsa(ref lsa) => lsa.to_bytes(writer)?,
        }

        let len = writer.bytes_written_since(&marker) + 20;
        writer.apply(marker).write_u16::<BE>(len as u16)?;

        Ok(())
    }
}

impl FromBytes for Lsa {
    type Error = io::Error;
    fn from_bytes(stream: &mut BytesReader) -> Result<Self, Self::Error> {
        let ls_age = Duration::from_secs(u64::from(stream.read_u16::<BE>()?));
        let typ = LsaType::from_bytes(stream)?;

        let link_state_id = stream.read_u32::<BE>()?;
        let advertising_router = stream.read_u32::<BE>()?;
        let ls_seq_no = stream.read_u32::<BE>()?;

        let _ = stream.read_u16::<BE>()?; // checksum
        let len = stream.read_u16::<BE>()? - 20;

        let content = stream.extract(len as usize, |body| match typ.code {
            KIND_ROUTER_LSA => Ok(LsaKind::RouterLsa(RouterLsa::from_bytes(body)?)),
            KIND_NETWORK_LSA => Ok(LsaKind::NetworkLsa(NetworkLsa::from_bytes(body)?)),
            KIND_INTER_AREA_PREFIX_LSA => Ok(LsaKind::InterAreaPrefixLsa(
                InterAreaPrefixLsa::from_bytes(body)?,
            )),
            KIND_INTER_AREA_ROUTER_LSA => Ok(LsaKind::InterAreaRouterLsa(
                InterAreaRouterLsa::from_bytes(body)?,
            )),
            KIND_AS_EXTERNAL_LSA => Ok(LsaKind::AsExternalLsa(AsExternalLsa::from_bytes(body)?)),
            KIND_LINK_LSA => Ok(LsaKind::LinkLsa(LinkLsa::from_bytes(body)?)),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid lsa type",
            )),
        })?;

        Ok(Lsa {
            header: LsaHeader {
                ls_age,
                link_state_id,
                advertising_router,
                ls_seq_no,
                flags: typ.flags,
            },
            content,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LsaType {
    pub flags: LasTypeFlags,
    pub code: u16, // u13
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct LasTypeFlags: u16 {
        const U     = 0b1000_0000_0000_0000;
        const S2    = 0b0100_0000_0000_0000;
        const S1    = 0b0010_0000_0000_0000;
    }
}

impl ToBytes for LsaType {
    type Error = io::Error;
    fn to_bytes(&self, writer: &mut BytesWriter) -> Result<(), Self::Error> {
        writer.write_u16::<BE>(self.flags.bits() | (self.code & 0x1FFF))?;
        Ok(())
    }
}

impl FromBytes for LsaType {
    type Error = io::Error;
    fn from_bytes(stream: &mut BytesReader) -> Result<Self, Self::Error> {
        let word = stream.read_u16::<BE>()?;
        Ok(Self {
            flags: LasTypeFlags::from_bits_truncate(word),
            code: word & 0x1FFF,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LsaDetachedHeader {
    pub ls_age: Duration,
    pub typ: LsaType,

    pub link_state_id: u32,
    pub advertising_router: u32,
    pub ls_seq_no: u32,

    // checksum
    pub length: u16,
}

impl From<Lsa> for LsaDetachedHeader {
    fn from(lsa: Lsa) -> Self {
        LsaDetachedHeader {
            ls_age: lsa.ls_age,
            typ: lsa.typ(),
            link_state_id: lsa.link_state_id,
            advertising_router: lsa.advertising_router,
            ls_seq_no: lsa.ls_seq_no,
            length: lsa.write_to_bytes().expect("cannot fail").len() as u16,
        }
    }
}

impl ToBytes for LsaDetachedHeader {
    type Error = io::Error;
    fn to_bytes(&self, writer: &mut BytesWriter) -> Result<(), Self::Error> {
        writer.write_u16::<BE>(self.ls_age.as_secs() as u16)?;
        self.typ.to_bytes(writer)?;

        writer.write_u32::<BE>(self.link_state_id)?;
        writer.write_u32::<BE>(self.advertising_router)?;
        writer.write_u32::<BE>(self.ls_seq_no)?;

        writer.write_u16::<BE>(0)?; // checksum
        writer.write_u16::<BE>(self.length)?; // length
        Ok(())
    }
}

impl FromBytes for LsaDetachedHeader {
    type Error = io::Error;
    fn from_bytes(stream: &mut BytesReader) -> Result<Self, Self::Error> {
        let ls_age = Duration::from_secs(u64::from(stream.read_u16::<BE>()?));
        let typ = LsaType::from_bytes(stream)?;

        let link_state_id = stream.read_u32::<BE>()?;
        let advertising_router = stream.read_u32::<BE>()?;
        let ls_seq_no = stream.read_u32::<BE>()?;

        let _ = stream.read_u16::<BE>()?; // checksum
        let length = stream.read_u16::<BE>()?;

        Ok(LsaDetachedHeader {
            ls_age,
            typ,
            link_state_id,
            advertising_router,
            ls_seq_no,
            length,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LsaKind {
    RouterLsa(RouterLsa),
    NetworkLsa(NetworkLsa),
    InterAreaPrefixLsa(InterAreaPrefixLsa),
    InterAreaRouterLsa(InterAreaRouterLsa),
    AsExternalLsa(AsExternalLsa),
    LinkLsa(LinkLsa),
}

const KIND_ROUTER_LSA: u16 = 1;
const KIND_NETWORK_LSA: u16 = 2;
const KIND_INTER_AREA_PREFIX_LSA: u16 = 3;
const KIND_INTER_AREA_ROUTER_LSA: u16 = 4;
const KIND_AS_EXTERNAL_LSA: u16 = 5;
const KIND_LINK_LSA: u16 = 8;

impl LsaKind {
    fn typ(&self) -> u16 {
        match self {
            LsaKind::RouterLsa(_) => KIND_ROUTER_LSA,
            LsaKind::NetworkLsa(_) => KIND_NETWORK_LSA,
            LsaKind::InterAreaPrefixLsa(_) => KIND_INTER_AREA_PREFIX_LSA,
            LsaKind::InterAreaRouterLsa(_) => KIND_INTER_AREA_ROUTER_LSA,
            LsaKind::AsExternalLsa(_) => KIND_AS_EXTERNAL_LSA,
            LsaKind::LinkLsa(_) => KIND_LINK_LSA,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouterLsa {
    pub flags: RouterLsaFlags,
    pub options: OspfOptions,
    pub links: Vec<RouterLsaLink>,
}

impl ToBytes for RouterLsa {
    type Error = io::Error;
    fn to_bytes(&self, writer: &mut BytesWriter) -> Result<(), Self::Error> {
        writer.write_u32::<BE>(self.flags.bits() | self.options.bits())?;
        for link in &self.links {
            link.to_bytes(writer)?;
        }
        Ok(())
    }
}

impl FromBytes for RouterLsa {
    type Error = io::Error;
    fn from_bytes(stream: &mut BytesReader) -> Result<Self, Self::Error> {
        let dword = stream.read_u32::<BE>()?;
        let mut links = Vec::new();
        while stream.has_remaining() {
            links.push(RouterLsaLink::from_bytes(stream)?);
        }
        Ok(Self {
            flags: RouterLsaFlags::from_bits_truncate(dword),
            options: OspfOptions::from_bits_truncate(dword),
            links,
        })
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct RouterLsaFlags: u32 {
        const VIRTUAL_LINK_ENDPOINT = 1 << 26;
        const EXTERNAL_BOUNDARY_ROUTER = 1 << 25;
        const AREA_BORDER_ROUTER = 1 << 24;
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouterLsaLink {
    pub link_typ: RouterLsaLinkType,
    // 0u8
    pub metric: u16,
    pub interface_id: u32,
    pub neighbor_interface_id: u32,
    pub neighbor_router_id: u32,
}

impl ToBytes for RouterLsaLink {
    type Error = io::Error;
    fn to_bytes(&self, writer: &mut BytesWriter) -> Result<(), Self::Error> {
        writer.write_u8(self.link_typ.to_raw_repr())?;
        writer.write_u8(0)?;
        writer.write_u16::<BE>(self.metric)?;

        writer.write_u32::<BE>(self.interface_id)?;
        writer.write_u32::<BE>(self.neighbor_interface_id)?;
        writer.write_u32::<BE>(self.neighbor_router_id)?;
        Ok(())
    }
}

impl FromBytes for RouterLsaLink {
    type Error = io::Error;
    fn from_bytes(stream: &mut BytesReader) -> Result<Self, Self::Error> {
        let link_typ = RouterLsaLinkType::from_raw_repr(stream.read_u8()?)?;
        let _ = stream.read_u8()?;
        let metric = stream.read_u16::<BE>()?;

        let interface_id = stream.read_u32::<BE>()?;
        let neighbor_interface_id = stream.read_u32::<BE>()?;
        let neighbor_router_id = stream.read_u32::<BE>()?;

        Ok(Self {
            link_typ,
            metric,
            interface_id,
            neighbor_interface_id,
            neighbor_router_id,
        })
    }
}

repr_enum! {
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum RouterLsaLinkType {
        type Repr = u8 where BE;

        PointToPoint = 1,
        ConnectToTransitNetwork = 2,
        ConnectToStubNetwork = 3,
        Virtual = 4,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkLsa {
    pub options: OspfOptions,
    pub attached_routers: Vec<RouterId>,
}

impl ToBytes for NetworkLsa {
    type Error = io::Error;
    fn to_bytes(&self, writer: &mut BytesWriter) -> Result<(), Self::Error> {
        writer.write_u32::<BE>(self.options.bits())?;
        for router in &self.attached_routers {
            writer.write_u32::<BE>(*router)?;
        }
        Ok(())
    }
}

impl FromBytes for NetworkLsa {
    type Error = io::Error;
    fn from_bytes(stream: &mut BytesReader) -> Result<Self, Self::Error> {
        let options = OspfOptions::from_bits_truncate(stream.read_u32::<BE>()?);
        let mut attached_routers = Vec::new();
        while stream.has_remaining() {
            attached_routers.push(RouterId::from(stream.read_u32::<BE>()?));
        }
        Ok(NetworkLsa {
            options,
            attached_routers,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterAreaPrefixLsa {
    pub metric: u32,
    pub prefix: Ipv6Prefix,
}

impl ToBytes for InterAreaPrefixLsa {
    type Error = io::Error;
    fn to_bytes(&self, writer: &mut BytesWriter) -> Result<(), Self::Error> {
        writer.write_u32::<BE>(self.metric & 0x00_ff_ff_ff)?;
        self.prefix.to_bytes(writer)
    }
}

impl FromBytes for InterAreaPrefixLsa {
    type Error = io::Error;
    fn from_bytes(stream: &mut BytesReader) -> Result<Self, Self::Error> {
        let metric = stream.read_u32::<BE>()? & 0x00_ff_ff_ff;
        let prefix = Ipv6Prefix::from_bytes(stream)?;
        Ok(InterAreaPrefixLsa { metric, prefix })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterAreaRouterLsa {
    pub options: OspfOptions,
    pub metric: u32,
    pub destination_router_id: u32,
}

impl ToBytes for InterAreaRouterLsa {
    type Error = io::Error;
    fn to_bytes(&self, writer: &mut BytesWriter) -> Result<(), Self::Error> {
        writer.write_u32::<BE>(self.options.bits())?;
        writer.write_u32::<BE>(self.metric & 0x00_ff_ff_ff)?;
        writer.write_u32::<BE>(self.destination_router_id)?;
        Ok(())
    }
}

impl FromBytes for InterAreaRouterLsa {
    type Error = io::Error;
    fn from_bytes(stream: &mut BytesReader) -> Result<Self, Self::Error> {
        let options = OspfOptions::from_bits_truncate(stream.read_u32::<BE>()?);
        let metric = stream.read_u32::<BE>()? & 0x00_ff_ff_ff;
        let destination_router_id = stream.read_u32::<BE>()?;
        Ok(InterAreaRouterLsa {
            options,
            metric,
            destination_router_id,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AsExternalLsa {
    pub metric: u32,
    pub metric_external: bool,
    pub prefix: Ipv6Prefix,
    pub fwd_addr: Option<Ipv6Addr>,
    pub external_route_tag: Option<u32>,
    pub reference_link_state_id: Option<(u16, u32)>, // (ls, additional)
}

bitflags! {
    struct AsExternalLsaFlags: u32 {
        const T = 0x01_00_00_00;
        const F = 0x02_00_00_00;
        const E = 0x04_00_00_00;
    }
}

impl ToBytes for AsExternalLsa {
    type Error = io::Error;
    fn to_bytes(&self, writer: &mut BytesWriter) -> Result<(), Self::Error> {
        let mut flags = AsExternalLsaFlags::empty();
        flags.set(AsExternalLsaFlags::E, self.metric_external);
        flags.set(AsExternalLsaFlags::F, self.fwd_addr.is_some());
        flags.set(AsExternalLsaFlags::T, self.external_route_tag.is_some());

        writer.write_u32::<BE>(flags.bits() | (self.metric & 0x00_ff_ff_ff))?;

        // a roundabout way, to insert the ls type into the encoding
        let mut buf = Vec::with_capacity(16);
        self.prefix.write_to(&mut buf)?;
        if let Some((ls, _)) = self.reference_link_state_id {
            (&mut buf[2..4]).write_u16::<BE>(ls)?;
        }
        writer.write_all(&buf)?;

        self.fwd_addr.map_or(Ok(()), |addr| addr.to_bytes(writer))?;
        self.external_route_tag
            .map_or(Ok(()), |tag| writer.write_u32::<BE>(tag))?;
        self.reference_link_state_id
            .map_or(Ok(()), |(_, additional)| writer.write_u32::<BE>(additional))?;

        Ok(())
    }
}

impl FromBytes for AsExternalLsa {
    type Error = io::Error;
    fn from_bytes(stream: &mut BytesReader) -> Result<Self, Self::Error> {
        let dword = stream.read_u32::<BE>()?;

        let referenced_ls_type = 0xff_ff & stream.peek().read_u32::<BE>()?;
        let prefix = Ipv6Prefix::from_bytes(stream)?;

        let flags = AsExternalLsaFlags::from_bits_truncate(dword);
        let metric = dword & 0x00_ff_ff_ff;

        let mut fwd_addr = None;
        let mut external_route_tag = None;
        let mut reference_link_state_id = None;

        if flags.contains(AsExternalLsaFlags::F) {
            fwd_addr = Some(Ipv6Addr::from_bytes(stream)?);
        }
        if flags.contains(AsExternalLsaFlags::T) {
            external_route_tag = Some(stream.read_u32::<BE>()?);
        }
        if referenced_ls_type != 0 {
            reference_link_state_id = Some((referenced_ls_type as u16, stream.read_u32::<BE>()?));
        }

        Ok(Self {
            metric,
            metric_external: flags.contains(AsExternalLsaFlags::E),
            prefix,
            fwd_addr,
            external_route_tag,
            reference_link_state_id,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkLsa {
    pub routing_prio: u8,
    pub options: OspfOptions,
    pub link_local_addr: Ipv6Addr,
    pub prefixes: Vec<Ipv6Prefix>,
}

impl ToBytes for LinkLsa {
    type Error = io::Error;
    fn to_bytes(&self, writer: &mut BytesWriter) -> Result<(), Self::Error> {
        writer.write_u32::<BE>((u32::from(self.routing_prio) << 24) | self.options.bits())?;
        self.link_local_addr.to_bytes(writer)?;
        writer.write_u32::<BE>(self.prefixes.len() as u32)?;
        for prefix in &self.prefixes {
            prefix.to_bytes(writer)?;
        }
        Ok(())
    }
}

impl FromBytes for LinkLsa {
    type Error = io::Error;
    fn from_bytes(stream: &mut BytesReader) -> Result<Self, Self::Error> {
        let dword = stream.read_u32::<BE>()?;
        let options = OspfOptions::from_bits_truncate(dword);
        let routing_prio = u8::try_from((0xff_00_00_00 & dword) >> 24).expect("cannot fail");
        let link_local_addr = Ipv6Addr::from_bytes(stream)?;
        let num_prefix = stream.read_u32::<BE>()? as usize;
        let mut prefixes = Vec::with_capacity(num_prefix);
        for _ in 0..num_prefix {
            prefixes.push(Ipv6Prefix::from_bytes(stream)?);
        }
        Ok(LinkLsa {
            routing_prio,
            options,
            link_local_addr,
            prefixes,
        })
    }
}

// #[derive(Debug, Clone, PartialEq, Eq)]
// pub struct IntraAreaPrefixLsa {
//     pub referenced_ls_type: u16,

// }

#[cfg(test)]
mod tests {
    use super::*;
    use bytes_io::assert_encoding_e2e;
    use rand::{Rng, rng};

    impl Lsa {
        pub fn random() -> Self {
            Lsa {
                header: LsaHeader {
                    ls_age: Duration::from_secs(rng().random::<u64>() % 200),
                    link_state_id: rng().random::<u32>(),
                    advertising_router: rng().random::<u32>(),
                    ls_seq_no: rng().random::<u32>(),
                    flags: LasTypeFlags::S1,
                },
                content: match [1, 2, 3, 4, 5, 8][rng().random::<u16>() as usize % 6] {
                    KIND_ROUTER_LSA => LsaKind::RouterLsa(RouterLsa::random()),
                    KIND_NETWORK_LSA => LsaKind::NetworkLsa(NetworkLsa::random()),
                    KIND_INTER_AREA_PREFIX_LSA => {
                        LsaKind::InterAreaPrefixLsa(InterAreaPrefixLsa::random())
                    }
                    KIND_INTER_AREA_ROUTER_LSA => {
                        LsaKind::InterAreaRouterLsa(InterAreaRouterLsa::random())
                    }
                    KIND_AS_EXTERNAL_LSA => LsaKind::AsExternalLsa(AsExternalLsa::random()),
                    KIND_LINK_LSA => LsaKind::LinkLsa(LinkLsa::random()),
                    v => unreachable!("r {v}"),
                },
            }
        }
    }

    #[test]
    fn e2e_encoding_lsa() {
        let fuzzed = std::iter::repeat_with(Lsa::random)
            .take(100)
            .collect::<Vec<_>>();

        assert_encoding_e2e(&fuzzed);
    }

    impl LsaDetachedHeader {
        pub fn random() -> Self {
            LsaDetachedHeader::from(Lsa::random())
        }
    }

    #[test]
    fn e2e_encoding_lsa_only_header() {
        let fuzzed = std::iter::repeat_with(LsaDetachedHeader::random)
            .take(100)
            .collect::<Vec<_>>();

        assert_encoding_e2e(&fuzzed);
    }

    impl RouterLsa {
        fn random() -> Self {
            RouterLsa {
                flags: RouterLsaFlags::from_bits_truncate(rng().random()),
                options: OspfOptions::from_bits_truncate(rng().random()),
                links: std::iter::repeat_with(RouterLsaLink::random)
                    .take((rng().random::<u8>() % 8) as usize)
                    .collect(),
            }
        }
    }

    #[test]
    fn e2e_encoding_router_lsa() {
        let fuzzed = std::iter::repeat_with(RouterLsa::random)
            .take(100)
            .collect::<Vec<_>>();

        assert_encoding_e2e(&fuzzed);
    }

    impl RouterLsaLink {
        fn random() -> Self {
            RouterLsaLink {
                link_typ: RouterLsaLinkType::from_raw_repr(1 + (rng().random::<u8>() % 4)).unwrap(),
                metric: rng().random::<u16>(),
                interface_id: rng().random::<u32>(),
                neighbor_router_id: rng().random::<u32>(),
                neighbor_interface_id: rng().random::<u32>(),
            }
        }
    }

    #[test]
    fn e2e_encoding_router_lsa_link() {
        let fuzzed = std::iter::repeat_with(RouterLsaLink::random)
            .take(100)
            .collect::<Vec<_>>();

        assert_encoding_e2e(&fuzzed);
    }

    impl NetworkLsa {
        fn random() -> Self {
            NetworkLsa {
                options: OspfOptions::from_bits_truncate(rng().random::<u32>().into()),
                attached_routers: std::iter::repeat_with(|| rng().random())
                    .take((rng().random::<u8>() % 3) as usize + 1)
                    .collect(),
            }
        }
    }

    #[test]
    fn e2e_encoding_network_lsa() {
        let fuzzed = std::iter::repeat_with(NetworkLsa::random)
            .take(100)
            .collect::<Vec<_>>();

        assert_encoding_e2e(&fuzzed);
    }

    impl InterAreaPrefixLsa {
        fn random() -> Self {
            InterAreaPrefixLsa {
                metric: rng().random::<u32>() & 0x00_ff_ff_ff,
                prefix: Ipv6Prefix::random(),
            }
        }
    }

    #[test]
    fn e2e_encoding_inter_area_prefix_lsa() {
        let fuzzed = std::iter::repeat_with(InterAreaPrefixLsa::random)
            .take(100)
            .collect::<Vec<_>>();

        assert_encoding_e2e(&fuzzed);
    }

    impl InterAreaRouterLsa {
        fn random() -> Self {
            InterAreaRouterLsa {
                options: OspfOptions::from_bits_truncate(rng().random()),
                metric: rng().random::<u32>() & 0x00_ff_ff_ff,
                destination_router_id: rng().random::<u32>(),
            }
        }
    }

    #[test]
    fn e2e_encoding_inter_area_router_lsa() {
        let fuzzed = std::iter::repeat_with(InterAreaRouterLsa::random)
            .take(100)
            .collect::<Vec<_>>();

        assert_encoding_e2e(&fuzzed);
    }

    impl AsExternalLsa {
        fn random() -> Self {
            AsExternalLsa {
                metric: rng().random::<u32>() & 0x00_ff_ff_ff,
                metric_external: rng().random(),
                prefix: Ipv6Prefix::random(),
                fwd_addr: Some(Ipv6Addr::from(rng().random::<u128>())),
                external_route_tag: Some(rng().random::<u32>()),
                reference_link_state_id: Some((
                    rng().random::<u16>() % 6 + 1,
                    rng().random::<u32>(),
                )),
            }
        }
    }

    #[test]
    fn e2e_encoding_external_lsa() {
        let fuzzed = std::iter::repeat_with(AsExternalLsa::random)
            .take(100)
            .collect::<Vec<_>>();

        assert_encoding_e2e(&fuzzed);
    }

    impl LinkLsa {
        fn random() -> Self {
            LinkLsa {
                options: OspfOptions::from_bits_truncate(rng().random()),
                routing_prio: rng().random(),
                link_local_addr: Ipv6Addr::from(rng().random::<u128>()),
                prefixes: std::iter::repeat_with(Ipv6Prefix::random)
                    .take((rng().random::<u8>() % 5) as usize + 1)
                    .collect(),
            }
        }
    }

    #[test]
    fn e2e_encoding_link_lsa() {
        let fuzzed = std::iter::repeat_with(LinkLsa::random)
            .take(100)
            .collect::<Vec<_>>();

        assert_encoding_e2e(&fuzzed);
    }
}
