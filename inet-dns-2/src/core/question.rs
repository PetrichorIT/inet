use crate::core::NsResourceRecord;

use super::{
    DnsResourceRecord, DnsString, DnsZoneResolver, QueryResponseKind, QuestionClass, QuestionTyp,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuestion {
    pub qname: DnsString,
    pub qclass: QuestionClass,
    pub qtyp: QuestionTyp,
}

impl DnsQuestion {
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
