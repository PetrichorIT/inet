use super::{
    DnsResourceRecord, DnsString, DnsZoneResolver, QueryResponseKind, QuestionClass, QuestionTyp,
    ResourceRecordTyp,
};
use crate::core::{CNameResourceRecord, NsResourceRecord};
use bytepack::{
    BytestreamReader, BytestreamWriter, FromBytestream, ReadBytesExt, ToBytestream, WriteBytesExt,
    BE,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuestion {
    pub qname: DnsString,
    pub qclass: QuestionClass,
    pub qtyp: QuestionTyp,
}

impl DnsQuestion {
    pub fn mutate_query(mut self, ctx: &DnsZoneResolver) -> DnsQuestion {
        use QuestionTyp::*;
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
                        return self;
                    }
                }

                self.qname = name.clone();
                self
            }
            _ => self,
        }
    }

    pub fn on_unanwsered(&self, ctx: &DnsZoneResolver) -> Vec<(DnsQuestion, QueryResponseKind)> {
        use QuestionTyp::*;
        match self.qtyp {
            A | AAAA => vec![(
                DnsQuestion {
                    qname: DnsString::new(
                        self.qname
                            .suffix(self.qname.labels() - ctx.zone.labels() - 1),
                    ),
                    qclass: self.qclass,
                    qtyp: QuestionTyp::NS,
                },
                QueryResponseKind::Auth,
            )],
            _ => Vec::new(),
        }
    }

    pub fn on_anwsered(
        &self,
        anwsers: &[DnsResourceRecord],
    ) -> Vec<(DnsQuestion, QueryResponseKind)> {
        use QuestionTyp::*;
        match self.qtyp {
            NS => anwsers
                .iter()
                .flat_map(|r| {
                    let ns = r.as_any().downcast_ref::<NsResourceRecord>().unwrap();
                    vec![
                        (
                            DnsQuestion {
                                qname: ns.nameserver.clone(),
                                qclass: self.qclass,
                                qtyp: QuestionTyp::A,
                            },
                            QueryResponseKind::Additional,
                        ),
                        (
                            DnsQuestion {
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

impl ToBytestream for DnsQuestion {
    type Error = std::io::Error;
    fn to_bytestream(&self, stream: &mut BytestreamWriter) -> Result<(), Self::Error> {
        self.qname.to_bytestream(stream)?;
        stream.write_u16::<BE>(self.qtyp.to_raw_repr())?;
        stream.write_u16::<BE>(self.qclass.to_raw_repr())?;
        Ok(())
    }
}

impl FromBytestream for DnsQuestion {
    type Error = std::io::Error;
    fn from_bytestream(stream: &mut BytestreamReader) -> Result<Self, Self::Error> {
        let qname = DnsString::from_bytestream(stream)?;

        let qtyp = QuestionTyp::from_raw_repr(stream.read_u16::<BE>()?).unwrap();
        let qclass = QuestionClass::from_raw_repr(stream.read_u16::<BE>()?).unwrap();

        Ok(DnsQuestion {
            qname,
            qtyp,
            qclass,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{AResourceRecord, RecordMap, ResourceRecordClass};
    use std::{io, net::Ipv4Addr};

    #[test]
    fn on_unanwsered_default() {
        let zone = DnsZoneResolver {
            db: RecordMap::from_iter(std::iter::empty()),
            zone: DnsString::new("com."),
        };
        let question = DnsQuestion {
            qtyp: QuestionTyp::NS,
            qname: DnsString::new("www.example.com."),
            qclass: QuestionClass::IN,
        };

        assert_eq!(question.on_unanwsered(&zone), []);
    }

    #[test]
    fn on_unanwsered_for_quetion_a_aaaa() {
        let zone = DnsZoneResolver {
            db: RecordMap::from_iter(std::iter::empty()),
            zone: DnsString::new("com."),
        };
        let question = DnsQuestion {
            qtyp: QuestionTyp::A,
            qname: DnsString::new("www.example.com."),
            qclass: QuestionClass::IN,
        };

        assert_eq!(
            question.on_unanwsered(&zone),
            [(
                DnsQuestion {
                    qtyp: QuestionTyp::NS,
                    qname: DnsString::new("example.com."),
                    qclass: QuestionClass::IN
                },
                QueryResponseKind::Auth
            )]
        );
    }

    #[test]
    fn on_anwsered_default() {
        let question = DnsQuestion {
            qtyp: QuestionTyp::A,
            qname: DnsString::new("www.example.com."),
            qclass: QuestionClass::IN,
        };
        let anwser = [AResourceRecord {
            name: DnsString::new("www.example.com"),
            class: ResourceRecordClass::IN,
            ttl: 0,
            addr: Ipv4Addr::new(10, 1, 3, 1),
        }
        .into()];

        assert_eq!(question.on_anwsered(&anwser), []);
    }

    #[test]
    fn on_anwsered_for_ns_record() {
        let question = DnsQuestion {
            qtyp: QuestionTyp::NS,
            qname: DnsString::new("example.com."),
            qclass: QuestionClass::IN,
        };
        let anwser = [NsResourceRecord {
            domain: DnsString::new("example.com."),
            class: ResourceRecordClass::IN,
            ttl: 0,
            nameserver: DnsString::new("ns0.example.com."),
        }
        .into()];

        assert_eq!(
            question.on_anwsered(&anwser),
            [
                (
                    DnsQuestion {
                        qtyp: QuestionTyp::A,
                        qname: DnsString::new("ns0.example.com."),
                        qclass: QuestionClass::IN
                    },
                    QueryResponseKind::Additional
                ),
                (
                    DnsQuestion {
                        qtyp: QuestionTyp::AAAA,
                        qname: DnsString::new("ns0.example.com."),
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
            DnsQuestion {
                qtyp: QuestionTyp::A,
                qname: DnsString::new("example.org."),
                qclass: QuestionClass::IN,
            },
            DnsQuestion {
                qtyp: QuestionTyp::NS,
                qname: DnsString::new("www.example.org."),
                qclass: QuestionClass::IN,
            },
            DnsQuestion {
                qtyp: QuestionTyp::CNAME,
                qname: DnsString::new("org."),
                qclass: QuestionClass::CH,
            },
        ];
        for example in examples {
            let e2e = DnsQuestion::from_slice(&example.to_vec()?)?;
            assert_eq!(example, e2e);
        }
        Ok(())
    }
}
