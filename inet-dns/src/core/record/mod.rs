use super::{string::DnsString, QuestionClass, QuestionTyp, ZonefileLineRecord};
use bytes_io::{BytesReader, BytesWriter, FromBytes, ReadBytesExt, ToBytes, WriteBytesExt, BE};
use macros::repr_enum;

use std::{
    any::Any,
    fmt::{self, Debug, Display},
    io::{self, Read, Write},
    ops::Deref,
};

mod addr;
mod cname;
mod ns;
mod opt;
mod ptr;
mod raw;
mod soa;
mod txt;

pub use addr::*;
pub use cname::*;
pub use ns::*;
pub use opt::*;
pub use ptr::*;
pub use soa::*;
pub use txt::*;

pub(crate) use raw::*;

/// A trait for arbitrary Resource Records
pub trait ResourceRecord: Debug + Send {
    fn name(&self) -> &DnsString;
    fn ttl(&self) -> Option<u32>;
    fn class(&self) -> Option<ResourceRecordClass>;
    fn typ(&self) -> ResourceRecordTyp;

    fn rdata(&self) -> Vec<u8>;
    fn rdata_fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result;

    fn as_any(&self) -> &dyn Any;
}

// # DnsResourceRecord (dyn)

/// A trait object for arbitrary Resource Records.
#[derive(Debug)]
pub struct DnsResourceRecord {
    inner: Box<dyn ResourceRecord>,
}

impl DnsResourceRecord {
    pub(crate) fn as_raw(&self) -> RawResourceRecord {
        RawResourceRecord {
            name: self.name().clone(),
            ttl: self.ttl().unwrap(),
            typ: self.typ(),
            class: self.class().unwrap(),
            rdata: self.rdata(),
        }
    }

    pub(crate) fn from_raw(raw: RawResourceRecord) -> io::Result<Self> {
        use ResourceRecordTyp::*;
        match raw.typ {
            A => AResourceRecord::try_from(raw).map(DnsResourceRecord::from),
            AAAA => AAAAResourceRecord::try_from(raw).map(DnsResourceRecord::from),
            NS => NsResourceRecord::try_from(raw).map(DnsResourceRecord::from),
            CNAME => CNameResourceRecord::try_from(raw).map(DnsResourceRecord::from),
            SOA => SoaResourceRecord::try_from(raw).map(DnsResourceRecord::from),
            PTR => PtrResourceRecord::try_from(raw).map(DnsResourceRecord::from),
            TXT => TxtResourceRecord::try_from(raw).map(DnsResourceRecord::from),
            OPT => OptResourceRecord::try_from(raw).map(DnsResourceRecord::from),

            _ => Ok(DnsResourceRecord::from(raw)),
        }
    }
}

impl Clone for DnsResourceRecord {
    fn clone(&self) -> Self {
        DnsResourceRecord::from_raw(self.as_raw()).expect("should not fail")
    }
}

impl Deref for DnsResourceRecord {
    type Target = dyn ResourceRecord;
    fn deref(&self) -> &Self::Target {
        &*self.inner
    }
}

impl PartialOrd for DnsResourceRecord {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for DnsResourceRecord {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.name().cmp(other.name())
    }
}

impl PartialEq for DnsResourceRecord {
    fn eq(&self, other: &Self) -> bool {
        self.as_raw().eq(&other.as_raw())
    }
}

impl Eq for DnsResourceRecord {}

impl<T> From<T> for DnsResourceRecord
where
    T: ResourceRecord + 'static,
{
    fn from(value: T) -> Self {
        Self {
            inner: Box::new(value),
        }
    }
}

impl TryFrom<ZonefileLineRecord> for DnsResourceRecord {
    type Error = io::Error;
    fn try_from(value: ZonefileLineRecord) -> Result<Self, Self::Error> {
        use ResourceRecordTyp::*;
        match value.typ {
            A => AResourceRecord::try_from(value).map(DnsResourceRecord::from),
            AAAA => AAAAResourceRecord::try_from(value).map(DnsResourceRecord::from),
            NS => NsResourceRecord::try_from(value).map(DnsResourceRecord::from),
            CNAME => CNameResourceRecord::try_from(value).map(DnsResourceRecord::from),
            SOA => SoaResourceRecord::try_from(value).map(DnsResourceRecord::from),
            PTR => PtrResourceRecord::try_from(value).map(DnsResourceRecord::from),
            TXT => TxtResourceRecord::try_from(value).map(DnsResourceRecord::from),
            _ => RawResourceRecord::try_from(value).map(DnsResourceRecord::from),
        }
    }
}

impl ToBytes for DnsResourceRecord {
    type Error = io::Error;
    fn to_bytes(&self, stream: &mut BytesWriter) -> Result<(), Self::Error> {
        self.inner.name().to_bytes(stream)?;

        stream.write_u16::<BE>(self.inner.typ() as u16)?;
        stream.write_u16::<BE>(
            self.inner
                .class()
                .expect("no class no support")
                .to_raw_repr(),
        )?;
        stream.write_u32::<BE>(self.inner.ttl().expect("no ttl no support"))?;

        stream.write_u16::<BE>(self.inner.rdata().len() as u16)?;
        stream.write_all(&self.inner.rdata())?;

        Ok(())
    }
}

impl FromBytes for DnsResourceRecord {
    type Error = io::Error;
    fn from_bytes(stream: &mut BytesReader) -> Result<Self, Self::Error> {
        let name = DnsString::from_bytes(stream)?;

        let typ = ResourceRecordTyp::from_raw_repr(stream.read_u16::<BE>()?)?;
        let class = ResourceRecordClass::from_raw_repr(stream.read_u16::<BE>()?)?;
        let ttl = stream.read_u32::<BE>()?;

        let len = stream.read_u16::<BE>()?;
        let mut rdata = vec![0; len as usize];
        stream.read_exact(&mut rdata)?;

        let raw = RawResourceRecord {
            name,
            ttl,
            typ,
            class,
            rdata,
        };

        Self::from_raw(raw)
    }
}

impl Display for DnsResourceRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:<20} \t{:<8} \t{:?} {:?}\t ",
            self.name(),
            self.ttl().unwrap_or(0),
            self.class().unwrap_or(ResourceRecordClass::IN),
            self.typ()
        )?;
        self.rdata_fmt(f)
    }
}

// # ResourceRecordClass / ResourceRecordTyp

repr_enum! {
    /// The class of a Resource Record.
    #[derive(Debug, Default,Clone, Copy, PartialEq, Eq, Hash)]
    pub enum ResourceRecordClass {
        type Repr = u16 where BE;
        #[default]
        IN = 1,
        CS = 2,
        CH = 3,
        HS = 4,

        = default OTHER
    }
}

impl TryFrom<QuestionClass> for ResourceRecordClass {
    type Error = io::Error;
    fn try_from(value: QuestionClass) -> Result<Self, Self::Error> {
        Self::from_raw_repr(value.to_raw_repr())
    }
}

repr_enum! {
    /// The type of a Resource Record.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub enum ResourceRecordTyp {
        type Repr = u16 where BE;

        A = 1,
        AAAA = 28,
        AFSDB = 18,
        APL = 42,
        CAA = 257,
        CDNSKEY = 60,
        CDS = 59,
        CERT = 37,
        CNAME = 5,
        CSYNC = 62,
        DHCID = 49,
        DLV = 32769,
        DNAME = 39,
        DNSKEY = 48,
        DS = 43,
        EUI48 = 108,
        EUI64 = 109,
        HINFO = 13,
        HIP = 55,
        HTTPS = 65,
        IPSECKEY = 45,
        KEY = 25,
        KX = 36,
        LOC = 29,
        MX = 15,
        NAPTR = 35,
        NS = 2,
        NSEC = 47,
        NSEC3 = 50,
        NSEC3PARAM = 51,
        OPENPGPKEY = 61,
        PTR = 12,
        RRSIG = 46,
        RP = 17,
        SIG = 24,
        SMIMEA = 53,
        SOA = 6,
        SRV = 33,
        SSHFP = 44,
        SVCB = 64,
        TA = 32768,
        TKEY = 249,
        TLSA = 52,
        TSIG = 250,
        TXT = 16,
        URI = 256,
        ZONEMD = 63,

        OPT = 41,
    }
}

impl TryFrom<QuestionTyp> for ResourceRecordTyp {
    type Error = io::Error;
    fn try_from(value: QuestionTyp) -> Result<Self, Self::Error> {
        Self::from_raw_repr(value.to_raw_repr())
    }
}

#[cfg(test)]
mod tests {
    use bytes_io::assert_encoding_e2e;

    use crate::core::Zonefile;
    use std::{
        net::{Ipv4Addr, Ipv6Addr},
        str::FromStr,
    };

    use super::*;

    const ZONEFILE_ROOT: &str = include_str!("../../examples/root.zone");
    const ZONEFILE_ORG: &str = include_str!("../../examples/org.zone");
    const ZONEFILE_EXAMPLE_ORG: &str = include_str!("../../examples/example.org.zone");

    #[test]
    fn encode_decode_rrs_as_bytestream() -> io::Result<()> {
        let zf1 = Zonefile::from_str(ZONEFILE_ROOT)?;
        let zf2 = Zonefile::from_str(ZONEFILE_ORG)?;
        let zf3 = Zonefile::from_str(ZONEFILE_EXAMPLE_ORG)?;

        for entry in zf1.records.iter().chain(&zf2.records).chain(&zf3.records) {
            let buf = entry.write_to_bytes()?;
            let decoded = DnsResourceRecord::peek_from(buf)?;
            assert_eq!(entry, &decoded);
        }

        Ok(())
    }

    #[test]
    fn encode_decode_rrs_as_raw_records() -> io::Result<()> {
        let zf1 = Zonefile::from_str(ZONEFILE_ROOT)?;
        let zf2 = Zonefile::from_str(ZONEFILE_ORG)?;
        let zf3 = Zonefile::from_str(ZONEFILE_EXAMPLE_ORG)?;

        for entry in zf1.records.iter().chain(&zf2.records).chain(&zf3.records) {
            let raw = entry.as_raw();
            let decoded = DnsResourceRecord::from_raw(raw)?;
            assert_eq!(entry, &decoded);
        }

        Ok(())
    }

    #[test]
    fn e2e_encoding_a_records() -> io::Result<()> {
        assert_encoding_e2e::<DnsResourceRecord, _>(&[
            AResourceRecord {
                name: "example.org.".parse()?,
                ttl: 3600,
                class: ResourceRecordClass::IN,
                addr: Ipv4Addr::new(192, 0, 2, 1),
            }
            .into(),
            AResourceRecord {
                name: "example.org.".parse()?,
                ttl: 3600,
                class: ResourceRecordClass::CH,
                addr: Ipv4Addr::new(192, 0, 133, 2),
            }
            .into(),
            AResourceRecord {
                name: ".".parse()?,
                ttl: 3600,
                class: ResourceRecordClass::IN,
                addr: Ipv4Addr::new(192, 123, 2, 3),
            }
            .into(),
        ]);
        Ok(())
    }

    #[test]
    fn e2e_encoding_aaaa_records() -> io::Result<()> {
        assert_encoding_e2e::<DnsResourceRecord, _>(&[
            AAAAResourceRecord {
                name: "example.org.".parse()?,
                ttl: 3600,
                class: ResourceRecordClass::IN,
                addr: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
            }
            .into(),
            AAAAResourceRecord {
                name: "example.org.".parse()?,
                ttl: 3600,
                class: ResourceRecordClass::CH,
                addr: Ipv6Addr::new(0x2001, 0xdb8, 0, 321, 0, 0, 0, 2),
            }
            .into(),
            AAAAResourceRecord {
                name: ".".parse()?,
                ttl: 3600,
                class: ResourceRecordClass::IN,
                addr: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 3),
            }
            .into(),
        ]);
        Ok(())
    }

    #[test]
    fn e2e_encoding_cname_records() -> io::Result<()> {
        assert_encoding_e2e::<DnsResourceRecord, _>(&[
            CNameResourceRecord {
                name: "example.org.".parse()?,
                ttl: 3600,
                class: ResourceRecordClass::IN,
                target: "example.com.".parse()?,
            }
            .into(),
            CNameResourceRecord {
                name: ".".parse()?,
                ttl: 3600,
                class: ResourceRecordClass::IN,
                target: "root.com.".parse()?,
            }
            .into(),
        ]);
        Ok(())
    }

    #[test]
    fn e2e_encoding_ns_records() -> io::Result<()> {
        assert_encoding_e2e::<DnsResourceRecord, _>(&[
            NsResourceRecord {
                domain: "example.org.".parse()?,
                ttl: 3600,
                class: ResourceRecordClass::IN,
                nameserver: "ns1.example.org.".parse()?,
            }
            .into(),
            NsResourceRecord {
                domain: "abc.example.org.".parse()?,
                ttl: 9000,
                class: ResourceRecordClass::HS,
                nameserver: "ns2.example.org.".parse()?,
            }
            .into(),
            NsResourceRecord {
                domain: ".".parse()?,
                ttl: 3600,
                class: ResourceRecordClass::IN,
                nameserver: "ns3.subdomain.lalala.very-deep.example.org.".parse()?,
            }
            .into(),
        ]);
        Ok(())
    }

    #[test]
    fn e2e_encoding_opt_records() -> io::Result<()> {
        assert_encoding_e2e::<DnsResourceRecord, _>(&[
            OptResourceRecord {
                name: ".".parse()?,
                udp_payload_size: 4096,
                rcode: 7,
                version: false,
                options: vec![],
            }
            .into(),
            OptResourceRecord {
                name: ".".parse()?,
                udp_payload_size: 1396,
                rcode: 73,
                version: true,
                options: vec![
                    Opt {
                        code: 1,
                        value: vec![1, 2, 3],
                    },
                    Opt {
                        code: 2,
                        value: vec![4, 5, 6],
                    },
                ],
            }
            .into(),
        ]);
        Ok(())
    }

    #[test]
    fn e2e_encoding_ptr_records() -> io::Result<()> {
        assert_encoding_e2e::<DnsResourceRecord, _>(&[
            PtrResourceRecord {
                name: "example.org.".parse()?,
                ttl: 3600,
                class: ResourceRecordClass::IN,
                addr: "192.168.2.1.".parse()?,
            }
            .into(),
            PtrResourceRecord {
                name: "www.example.org.".parse()?,
                ttl: 31233,
                class: ResourceRecordClass::CS,
                addr: "192.33.12.1.".parse()?,
            }
            .into(),
        ]);
        Ok(())
    }

    #[test]
    fn e2e_encoding_soa_records() -> io::Result<()> {
        assert_encoding_e2e::<DnsResourceRecord, _>(&[SoaResourceRecord {
            name: "example.org.".parse()?,
            ttl: 3600,
            class: ResourceRecordClass::IN,
            mname: "a@mail.com".parse()?,
            rname: "b@mail.com".parse()?,
            serial: 1,
            refresh: 2,
            retry: 3,
            expire: 4,
            minimum: 5,
        }
        .into()]);
        Ok(())
    }

    #[test]
    fn e2e_encoding_txt_records() -> io::Result<()> {
        assert_encoding_e2e::<DnsResourceRecord, _>(&[TxtResourceRecord {
            name: "example.org.".parse()?,
            ttl: 3600,
            class: ResourceRecordClass::IN,
            text: "example text tralal".to_string(),
        }
        .into()]);
        Ok(())
    }
}
