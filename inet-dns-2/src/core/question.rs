use std::fmt::Display;

use super::{
    DnsResourceRecord, DnsString, QueryResponseKind, ResourceRecordClass, ResourceRecordTyp,
    ZoneResolver,
};
use crate::core::{CNameResourceRecord, NsResourceRecord};
use bytepack::{
    raw_enum, BytestreamReader, BytestreamWriter, FromBytestream, ReadBytesExt, ToBytestream,
    WriteBytesExt, BE,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
    pub qname: DnsString,
    pub qclass: QuestionClass,
    pub qtyp: QuestionTyp,
}

impl Question {
    pub fn mutate_query(&self, ctx: &ZoneResolver) -> Question {
        use QuestionTyp::*;
        let mut this = self.clone();
        match self.qtyp {
            A | AAAA => {
                let mut name = &self.qname;
                let mut i = 0;
                while let Some(cname) = ctx.db.get(name, ResourceRecordTyp::CNAME).first() {
                    name = &cname
                        .as_any()
                        .downcast_ref::<CNameResourceRecord>()
                        .expect("must be CNAME")
                        .target;
                    i += 1;
                    if i > 32 {
                        // TODO: ERR
                        return this;
                    }
                }

                this.qname = name.clone();
                this
            }
            _ => this,
        }
    }

    pub fn on_unanwsered(&self, ctx: &ZoneResolver) -> Vec<(Question, QueryResponseKind)> {
        use QuestionTyp::*;
        match self.qtyp {
            A | AAAA => {
                let mut buf = Vec::new();
                for k in (ctx.zone.labels().len() + 1)..self.qname.labels().len() {
                    let qname = self.qname.truncated(k);
                    buf.push((
                        Question {
                            qname,
                            qclass: self.qclass,
                            qtyp: QuestionTyp::NS,
                        },
                        QueryResponseKind::Auth,
                    ));
                }
                buf
            }
            _ => Vec::new(),
        }
    }

    pub fn on_anwsered(&self, anwsers: &[DnsResourceRecord]) -> Vec<(Question, QueryResponseKind)> {
        use QuestionTyp::*;
        match self.qtyp {
            A => vec![(
                Question {
                    qname: self.qname.clone(),
                    qtyp: AAAA,
                    qclass: self.qclass,
                },
                QueryResponseKind::Additional,
            )],

            AAAA => vec![(
                Question {
                    qname: self.qname.clone(),
                    qtyp: A,
                    qclass: self.qclass,
                },
                QueryResponseKind::Additional,
            )],

            NS => anwsers
                .iter()
                .flat_map(|r| {
                    let ns = r.as_any().downcast_ref::<NsResourceRecord>().unwrap();
                    vec![
                        (
                            Question {
                                qname: ns.nameserver.clone(),
                                qclass: self.qclass,
                                qtyp: QuestionTyp::A,
                            },
                            QueryResponseKind::Additional,
                        ),
                        (
                            Question {
                                qname: ns.nameserver.clone(),
                                qclass: self.qclass,
                                qtyp: QuestionTyp::AAAA,
                            },
                            QueryResponseKind::Additional,
                        ),
                    ]
                })
                .collect(),
            _ => Vec::new(),
        }
    }
}

impl ToBytestream for Question {
    type Error = std::io::Error;
    fn to_bytestream(&self, stream: &mut BytestreamWriter) -> Result<(), Self::Error> {
        self.qname.to_bytestream(stream)?;
        stream.write_u16::<BE>(self.qtyp.to_raw_repr())?;
        stream.write_u16::<BE>(self.qclass.to_raw_repr())?;
        Ok(())
    }
}

impl FromBytestream for Question {
    type Error = std::io::Error;
    fn from_bytestream(stream: &mut BytestreamReader) -> Result<Self, Self::Error> {
        let qname = DnsString::from_bytestream(stream)?;

        let qtyp = QuestionTyp::from_raw_repr(stream.read_u16::<BE>()?).unwrap();
        let qclass = QuestionClass::from_raw_repr(stream.read_u16::<BE>()?).unwrap();

        Ok(Question {
            qname,
            qtyp,
            qclass,
        })
    }
}

impl Display for Question {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?} {:?} {}", self.qtyp, self.qclass, self.qname)
    }
}

raw_enum! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub enum QuestionClass {
        type Repr = u16 where BE;
        IN = 1,
        CS = 2,
        CH = 3,
        HS = 4,

        ANY = 255,
    }
}

impl QuestionClass {
    pub fn includes(&self, class: ResourceRecordClass) -> bool {
        match self {
            QuestionClass::ANY => true,
            v => *v == QuestionClass::from(class),
        }
    }
}

impl From<ResourceRecordClass> for QuestionClass {
    fn from(value: ResourceRecordClass) -> Self {
        QuestionClass::from_raw_repr(value.to_raw_repr()).expect("should never fail")
    }
}

raw_enum! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub enum QuestionTyp {
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

        AXFR = 252,
        MAILB = 253,
        MAILA = 254,
        ANY = 255,
    }
}

impl From<ResourceRecordTyp> for QuestionTyp {
    fn from(value: ResourceRecordTyp) -> Self {
        QuestionTyp::from_raw_repr(value.to_raw_repr()).expect("should never fail")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{AResourceRecord, RecordMap, ResourceRecordClass};
    use std::{io, net::Ipv4Addr, str::FromStr};

    #[test]
    fn on_unanwsered_default() {
        let zone = ZoneResolver {
            db: RecordMap::from_iter(std::iter::empty()),
            zone: "com.".parse().unwrap(),
        };
        let question = Question {
            qtyp: QuestionTyp::NS,
            qname: "www.example.com.".parse().unwrap(),
            qclass: QuestionClass::IN,
        };

        assert_eq!(question.on_unanwsered(&zone), []);
    }

    #[test]
    fn on_unanwsered_for_quetion_a_aaaa() {
        let zone = ZoneResolver {
            db: RecordMap::from_iter(std::iter::empty()),
            zone: "com.".parse().unwrap(),
        };
        let question = Question {
            qtyp: QuestionTyp::A,
            qname: "www.example.com.".parse().unwrap(),
            qclass: QuestionClass::IN,
        };

        assert_eq!(
            question.on_unanwsered(&zone),
            [(
                Question {
                    qtyp: QuestionTyp::NS,
                    qname: "example.com.".parse().unwrap(),
                    qclass: QuestionClass::IN
                },
                QueryResponseKind::Auth
            )]
        );
    }

    #[test]
    fn on_anwsered_default() {
        let question = Question {
            qtyp: QuestionTyp::A,
            qname: "www.example.com.".parse().unwrap(),
            qclass: QuestionClass::IN,
        };
        let anwser = [AResourceRecord {
            name: "www.example.com".parse().unwrap(),
            class: ResourceRecordClass::IN,
            ttl: 0,
            addr: Ipv4Addr::new(10, 1, 3, 1),
        }
        .into()];

        assert_eq!(
            question.on_anwsered(&anwser),
            [(
                Question {
                    qname: DnsString::from_str("www.example.com.").unwrap(),
                    qclass: QuestionClass::IN,
                    qtyp: QuestionTyp::AAAA
                },
                QueryResponseKind::Additional
            )]
        );
    }

    #[test]
    fn on_anwsered_for_ns_record() {
        let question = Question {
            qtyp: QuestionTyp::NS,
            qname: "example.com.".parse().unwrap(),
            qclass: QuestionClass::IN,
        };
        let anwser = [NsResourceRecord {
            domain: "example.com.".parse().unwrap(),
            class: ResourceRecordClass::IN,
            ttl: 0,
            nameserver: "ns0.example.com.".parse().unwrap(),
        }
        .into()];

        assert_eq!(
            question.on_anwsered(&anwser),
            [
                (
                    Question {
                        qtyp: QuestionTyp::A,
                        qname: "ns0.example.com.".parse().unwrap(),
                        qclass: QuestionClass::IN
                    },
                    QueryResponseKind::Additional
                ),
                (
                    Question {
                        qtyp: QuestionTyp::AAAA,
                        qname: "ns0.example.com.".parse().unwrap(),
                        qclass: QuestionClass::IN
                    },
                    QueryResponseKind::Additional
                )
            ]
        );
    }

    #[test]
    fn byte_encoding_e2e() -> io::Result<()> {
        let examples = [
            Question {
                qtyp: QuestionTyp::A,
                qname: "example.org.".parse().unwrap(),
                qclass: QuestionClass::IN,
            },
            Question {
                qtyp: QuestionTyp::NS,
                qname: "www.example.org.".parse().unwrap(),
                qclass: QuestionClass::IN,
            },
            Question {
                qtyp: QuestionTyp::CNAME,
                qname: "org.".parse().unwrap(),
                qclass: QuestionClass::CH,
            },
        ];
        for example in examples {
            let e2e = Question::from_slice(&example.to_vec()?)?;
            assert_eq!(example, e2e);
        }
        Ok(())
    }
}
