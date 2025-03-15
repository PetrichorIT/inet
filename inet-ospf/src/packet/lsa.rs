use std::{
    io::{self, Write},
    net::Ipv4Addr,
    time::Duration,
};

use bitflags::bitflags;
use bytes_io::{BE, BytesReader, BytesWriter, FromBytes, ReadBytesExt, ToBytes, WriteBytesExt};
use macros::repr_enum;

use super::{OspfOptions, RouterId};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lsa {
    pub ls_age: Duration,
    pub options: OspfOptions,
    pub link_state_id: u32,
    pub advertising_router: u32,
    pub ls_seq_no: u32,
    // checksum: u16
    // length: u16 including 20 byte header
    pub content: LsaKind,
}

impl ToBytes for Lsa {
    type Error = io::Error;

    fn to_bytes(&self, writer: &mut BytesWriter) -> Result<(), Self::Error> {
        writer.write_u16::<BE>(self.ls_age.as_secs() as u16)?;
        writer.write_u8(self.options.bits())?;
        writer.write_u8(self.content.typ())?;

        writer.write_u32::<BE>(self.link_state_id)?;
        writer.write_u32::<BE>(self.advertising_router)?;
        writer.write_u32::<BE>(self.ls_seq_no)?;

        writer.write_u16::<BE>(0)?; // checksum
        let marker = writer.marker::<u16>();

        match self.content {
            LsaKind::RouterLsa(ref lsa) => lsa.to_bytes(writer)?,
            LsaKind::NetworkLsa(ref lsa) => lsa.to_bytes(writer)?,
            LsaKind::SummaryLsa(ref lsa) => lsa.to_bytes(writer)?,
            LsaKind::SummaryLsaAsbr(ref lsa) => lsa.to_bytes(writer)?,
            LsaKind::AsExternalLsa(ref lsa) => lsa.to_bytes(writer)?,
        }

        let len = writer.bytes_written_since(&marker) + 20;
        writer.apply(marker).write_u16::<BE>(len as u16)?;

        Ok(())
    }
}

impl FromBytes for Lsa {
    type Error = io::Error;
    fn from_bytes(stream: &mut BytesReader) -> Result<Self, Self::Error> {
        let ls_age = Duration::from_secs(stream.read_u16::<BE>()? as u64);
        let options = OspfOptions::from_bits_truncate(stream.read_u8()?);
        let typ = stream.read_u8()?;

        let link_state_id = stream.read_u32::<BE>()?;
        let advertising_router = stream.read_u32::<BE>()?;
        let ls_seq_no = stream.read_u32::<BE>()?;

        let _ = stream.read_u16::<BE>()?; // checksum
        let len = stream.read_u16::<BE>()? - 20;

        let content = stream.extract(len as usize, |body| match typ {
            KIND_ROUTER_LSA => Ok(LsaKind::RouterLsa(RouterLsa::from_bytes(body)?)),
            KIND_NETWORK_LSA => Ok(LsaKind::NetworkLsa(NetworkLsa::from_bytes(body)?)),
            KIND_SUMMARY_LSA => Ok(LsaKind::SummaryLsa(SummaryLsa::from_bytes(body)?)),
            KIND_SUMMARY_LSA_ASBR => Ok(LsaKind::SummaryLsaAsbr(SummaryLsa::from_bytes(body)?)),
            KIND_AS_EXTERNAL_LSA => Ok(LsaKind::AsExternalLsa(AsExternalLsa::from_bytes(body)?)),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid lsa type",
            )),
        })?;

        Ok(Lsa {
            ls_age,
            options,
            link_state_id,
            advertising_router,
            ls_seq_no,
            content,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LsaOnlyHeader {
    pub ls_age: Duration,
    pub typ: u8,
    pub options: OspfOptions,
    pub link_state_id: u32,
    pub advertising_router: u32,
    pub ls_seq_no: u32,
    pub length: u16,
}

impl From<Lsa> for LsaOnlyHeader {
    fn from(lsa: Lsa) -> Self {
        LsaOnlyHeader {
            ls_age: lsa.ls_age,
            typ: lsa.content.typ(),
            options: lsa.options,
            link_state_id: lsa.link_state_id,
            advertising_router: lsa.advertising_router,
            ls_seq_no: lsa.ls_seq_no,
            length: lsa.write_to_bytes().expect("cannot fail").len() as u16,
        }
    }
}

impl ToBytes for LsaOnlyHeader {
    type Error = io::Error;
    fn to_bytes(&self, writer: &mut BytesWriter) -> Result<(), Self::Error> {
        writer.write_u16::<BE>(self.ls_age.as_secs() as u16)?;
        writer.write_u8(self.options.bits())?;
        writer.write_u8(self.typ)?;

        writer.write_u32::<BE>(self.link_state_id)?;
        writer.write_u32::<BE>(self.advertising_router)?;
        writer.write_u32::<BE>(self.ls_seq_no)?;

        writer.write_u16::<BE>(0)?; // checksum
        writer.write_u16::<BE>(self.length)?; // length
        Ok(())
    }
}

impl FromBytes for LsaOnlyHeader {
    type Error = io::Error;
    fn from_bytes(stream: &mut BytesReader) -> Result<Self, Self::Error> {
        let ls_age = Duration::from_secs(stream.read_u16::<BE>()? as u64);
        let options = OspfOptions::from_bits_truncate(stream.read_u8()?);
        let typ = stream.read_u8()?;

        let link_state_id = stream.read_u32::<BE>()?;
        let advertising_router = stream.read_u32::<BE>()?;
        let ls_seq_no = stream.read_u32::<BE>()?;

        let _ = stream.read_u16::<BE>()?; // checksum
        let length = stream.read_u16::<BE>()?;

        Ok(LsaOnlyHeader {
            ls_age,
            options,
            link_state_id,
            advertising_router,
            ls_seq_no,
            typ,
            length,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LsaKind {
    RouterLsa(RouterLsa),
    NetworkLsa(NetworkLsa),
    SummaryLsa(SummaryLsa),
    SummaryLsaAsbr(SummaryLsa),
    AsExternalLsa(AsExternalLsa),
}

const KIND_ROUTER_LSA: u8 = 1;
const KIND_NETWORK_LSA: u8 = 2;
const KIND_SUMMARY_LSA: u8 = 3;
const KIND_SUMMARY_LSA_ASBR: u8 = 4;
const KIND_AS_EXTERNAL_LSA: u8 = 5;

impl LsaKind {
    fn typ(&self) -> u8 {
        match self {
            LsaKind::RouterLsa(_) => KIND_ROUTER_LSA,
            LsaKind::NetworkLsa(_) => KIND_NETWORK_LSA,
            LsaKind::SummaryLsa(_) => KIND_SUMMARY_LSA,
            LsaKind::SummaryLsaAsbr(_) => KIND_SUMMARY_LSA_ASBR,
            LsaKind::AsExternalLsa(_) => KIND_AS_EXTERNAL_LSA,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouterLsa {
    pub flags: RouterLsaFlags,
    pub links: Vec<RouterLsaLink>,
}

impl ToBytes for RouterLsa {
    type Error = io::Error;
    fn to_bytes(&self, writer: &mut BytesWriter) -> Result<(), Self::Error> {
        writer.write_u16::<BE>(self.flags.bits())?;
        writer.write_u16::<BE>(self.links.len() as u16)?;
        for link in &self.links {
            link.to_bytes(writer)?;
        }
        Ok(())
    }
}

impl FromBytes for RouterLsa {
    type Error = io::Error;
    fn from_bytes(stream: &mut BytesReader) -> Result<Self, Self::Error> {
        let flags = RouterLsaFlags::from_bits_truncate(stream.read_u16::<BE>()?);
        let num_links = stream.read_u16::<BE>()?;
        let mut links = Vec::with_capacity(num_links as usize);
        for _ in 0..num_links {
            links.push(RouterLsaLink::from_bytes(stream)?);
        }
        Ok(Self { flags, links })
    }
}

bitflags! {
    pub struct RouterLsaFlags: u16 {
        const VIRTUAL_LINK_ENDPOINT = 1 << 10;
        const EXTERNAL_BOUNDARY_ROUTER = 1 << 9;
        const AREA_BORDER_ROUTER = 1 << 8;
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouterLsaLink {
    pub link_id: u32,
    pub link_data: [u8; 4],
    pub link_typ: RouterLsaLinkType,
    pub tos: u8,
    pub metric: u16,
}

impl ToBytes for RouterLsaLink {
    type Error = io::Error;
    fn to_bytes(&self, writer: &mut BytesWriter) -> Result<(), Self::Error> {
        writer.write_u32::<BE>(self.link_id)?;
        writer.write_all(&self.link_data)?;

        writer.write_u8(self.link_typ.to_raw_repr())?;
        writer.write_u8(self.tos)?;
        writer.write_u16::<BE>(self.metric)?; // probably must be 0 , or we must implement more TOS metrics

        Ok(())
    }
}

impl FromBytes for RouterLsaLink {
    type Error = io::Error;
    fn from_bytes(stream: &mut BytesReader) -> Result<Self, Self::Error> {
        let link_id = stream.read_u32::<BE>()?;
        let link_data = stream.read_u32::<BE>()?;
        let typ = RouterLsaLinkType::from_raw_repr(stream.read_u8()?)?;
        let tos = stream.read_u8()?;
        let metric = stream.read_u16::<BE>()?;
        Ok(Self {
            link_id,
            link_data: link_data.to_be_bytes(),
            link_typ: typ,
            tos,
            metric,
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
    pub netmask: Ipv4Addr,
    pub attached_routers: Vec<RouterId>,
}

impl ToBytes for NetworkLsa {
    type Error = io::Error;
    fn to_bytes(&self, writer: &mut BytesWriter) -> Result<(), Self::Error> {
        self.netmask.to_bytes(writer)?;
        for router in &self.attached_routers {
            writer.write_u32::<BE>(*router)?;
        }
        Ok(())
    }
}

impl FromBytes for NetworkLsa {
    type Error = io::Error;
    fn from_bytes(stream: &mut BytesReader) -> Result<Self, Self::Error> {
        let netmask = Ipv4Addr::from(stream.read_u32::<BE>()?);
        let mut attached_routers = Vec::new();
        while stream.has_remaining() {
            attached_routers.push(RouterId::from(stream.read_u32::<BE>()?));
        }
        Ok(NetworkLsa {
            netmask,
            attached_routers,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SummaryLsa {
    pub netmask: Ipv4Addr,
    pub metrics: Vec<(u32, u8)>, // first TOS must be 0
}

impl ToBytes for SummaryLsa {
    type Error = io::Error;
    fn to_bytes(&self, writer: &mut BytesWriter) -> Result<(), Self::Error> {
        writer.write_u32::<BE>(u32::from(self.netmask))?;
        if self.metrics.first().map_or(true, |(_, tos)| *tos != 0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "first TOS must be 0",
            ));
        }

        for (metric, tos) in &self.metrics {
            writer.write_u32::<BE>(((*tos as u32) << 24) | (metric & 0x00_ff_ff_ff))?;
        }
        Ok(())
    }
}

impl FromBytes for SummaryLsa {
    type Error = io::Error;
    fn from_bytes(reader: &mut BytesReader) -> Result<Self, Self::Error> {
        let netmask = Ipv4Addr::from(reader.read_u32::<BE>()?);
        let mut metrics = Vec::new();
        while reader.has_remaining() {
            let dword = reader.read_u32::<BE>()?;
            let tos = ((dword & 0xff_00_00_00) >> 24) as u8;
            let metric = dword & 0x00_ff_ff_ff;
            metrics.push((metric, tos));
        }

        if metrics.first().map_or(true, |(_, tos)| *tos != 0) {
            dbg!(metrics);
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "first TOS must be 0",
            ));
        }

        Ok(SummaryLsa { netmask, metrics })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AsExternalLsa {
    pub netmask: Ipv4Addr,
    pub components: Vec<AsExternal>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AsExternal {
    pub metric: u32, // u24,
    pub tos: u8,     // u7
    pub metric_external: bool,
    pub fwd_addr: Ipv4Addr,
    pub external_route_tag: u32,
}

impl ToBytes for AsExternalLsa {
    type Error = io::Error;
    fn to_bytes(&self, writer: &mut BytesWriter) -> Result<(), Self::Error> {
        writer.write_u32::<BE>(u32::from(self.netmask))?;

        for comp in &self.components {
            let overlay = comp.metric_external.then_some(0x80_00_00_00).unwrap_or(0)
                | (comp.tos as u32 & 0x7f) << 24;
            writer.write_u32::<BE>((0x00_ff_ff_ff & comp.metric) | overlay)?;

            writer.write_u32::<BE>(u32::from(comp.fwd_addr))?;
            writer.write_u32::<BE>(comp.external_route_tag)?;
        }

        Ok(())
    }
}

impl FromBytes for AsExternalLsa {
    type Error = io::Error;
    fn from_bytes(stream: &mut BytesReader) -> Result<Self, Self::Error> {
        let netmask = Ipv4Addr::from(stream.read_u32::<BE>()?);
        let mut components = Vec::new();
        while stream.has_remaining() {
            let dword = stream.read_u32::<BE>()?;
            let fwd_addr = Ipv4Addr::from(stream.read_u32::<BE>()?);
            let external_route_tag = stream.read_u32::<BE>()?;

            let metric_external = dword & 0x80_00_00_00 != 0;
            let tos = u8::try_from((dword & 0x7f_00_00_00) >> 24).expect("must work");
            let metric = dword & 0x00_ff_ff_ff;

            components.push(AsExternal {
                metric,
                metric_external,
                tos,
                fwd_addr,
                external_route_tag,
            })
        }

        Ok(Self {
            netmask,
            components,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes_io::assert_encoding_e2e;
    use rand::{Rng, rng};

    impl Lsa {
        pub fn random() -> Self {
            Lsa {
                ls_age: Duration::from_secs(rng().random::<u64>() % 200),
                options: OspfOptions::from_bits_truncate(rng().random()),
                link_state_id: rng().random::<u32>(),
                advertising_router: rng().random::<u32>(),
                ls_seq_no: rng().random::<u32>(),
                content: match 1 + rng().random::<u8>() % 5 {
                    KIND_ROUTER_LSA => LsaKind::RouterLsa(RouterLsa::random()),
                    KIND_NETWORK_LSA => LsaKind::NetworkLsa(NetworkLsa::random()),
                    KIND_SUMMARY_LSA => LsaKind::SummaryLsa(SummaryLsa::random()),
                    KIND_SUMMARY_LSA_ASBR => LsaKind::SummaryLsaAsbr(SummaryLsa::random()),
                    KIND_AS_EXTERNAL_LSA => LsaKind::AsExternalLsa(AsExternalLsa::random()),
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

    impl LsaOnlyHeader {
        pub fn random() -> Self {
            LsaOnlyHeader::from(Lsa::random())
        }
    }

    #[test]
    fn e2e_encoding_lsa_only_header() {
        let fuzzed = std::iter::repeat_with(LsaOnlyHeader::random)
            .take(100)
            .collect::<Vec<_>>();

        assert_encoding_e2e(&fuzzed);
    }

    impl RouterLsa {
        fn random() -> Self {
            RouterLsa {
                flags: RouterLsaFlags::from_bits_truncate(rng().random()),
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
                link_id: rng().random::<u32>().into(),
                link_data: rng().random::<u32>().to_be_bytes(),
                link_typ: RouterLsaLinkType::from_raw_repr(1 + (rng().random::<u8>() % 4)).unwrap(),
                tos: 0,
                metric: rng().random::<u16>(),
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
                netmask: rng().random::<u32>().into(),
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

    impl SummaryLsa {
        fn random() -> Self {
            SummaryLsa {
                netmask: rng().random::<u32>().into(),
                metrics: std::iter::once((rng().random::<u32>() & 0x00_ff_ff_ff, 0))
                    .chain(
                        std::iter::repeat_with(|| {
                            (rng().random::<u32>() & 0x00_ff_ff_ff, rng().random())
                        })
                        .take((rng().random::<u8>() % 4) as usize),
                    )
                    .collect(),
            }
        }
    }

    #[test]
    fn e2e_encoding_summary_lsa() {
        let fuzzed = std::iter::repeat_with(SummaryLsa::random)
            .take(100)
            .collect::<Vec<_>>();

        assert_encoding_e2e(&fuzzed);
    }

    impl AsExternalLsa {
        fn random() -> Self {
            AsExternalLsa {
                netmask: rng().random::<u32>().into(),
                components: std::iter::repeat_with(AsExternal::random)
                    .take((rng().random::<u8>() % 3) as usize + 1)
                    .collect(),
            }
        }
    }

    impl AsExternal {
        fn random() -> Self {
            AsExternal {
                metric: rng().random::<u32>() & 0x00_ff_ff_ff,
                tos: rng().random::<u8>() & 0x7f,
                metric_external: rng().random(),
                fwd_addr: rng().random::<u32>().into(),
                external_route_tag: rng().random(),
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
}
