use std::io;

mod db;
mod question;
mod record;
mod respone;
mod types;
mod zonefile;

pub use db::*;
pub use question::*;
pub use record::*;
pub use respone::*;
pub use types::*;
pub use zonefile::*;

pub struct DnsZoneResolver {
    // dbs: FxHashMap<ResourceRecordClass, RecordMap>,
    db: RecordMap,
    zone: DnsString,
}

impl DnsZoneResolver {
    pub fn new(zf: Zonefile) -> io::Result<Self> {
        let db = zf.records.into_iter().collect::<RecordMap>();

        let soa = db.soa().expect("expected soa");
        Ok(Self {
            zone: soa.name().clone(),
            db,
        })
    }

    pub fn query(&self, question: DnsQuestion) -> QueryResponse {
        if DnsString::suffix_match_len(&self.zone, &question.qname) < self.zone.labels() {
            return QueryResponse::default();
        }

        let question = question.mutate_query(self);
        self.query_inner(question)
    }

    fn query_inner(&self, question: DnsQuestion) -> QueryResponse {
        let mut response = QueryResponse {
            questions: vec![question.clone()],
            ..Default::default()
        };
        let results = self.db.query(&question);

        if results.is_empty() {
            for (follow_up, kind) in question.on_unanwsered(self) {
                let follow_up_result = self.db.query(&follow_up);
                if !follow_up_result.is_empty() {
                    response.include(follow_up_result, kind);
                    for (additional, kind) in follow_up.on_anwsered(follow_up_result) {
                        response.include(self.db.query(&additional), kind);
                    }
                }
            }
        } else {
            response.anwsers.extend(results.iter().cloned());
            for (additional, kind) in question.on_anwsered(results) {
                response.include(self.db.query(&additional), kind);
            }
        }

        response
    }
}

#[cfg(test)]
mod tests {
    use std::{net::Ipv4Addr, str::FromStr};

    use super::*;

    const ZONEFILE_ORG: &str = r#"
org. 7000 IN SOA ns0.namservers.org admin@org.org (7000 7000 7000 7000 7000)

org. 7000 IN NS ns0.nameservers.org.
example.org. 7000 IN NS ns1.example.org.
example.org. 7000 IN NS ns2.example.org.

ns1.example.org. 7000 IN A 100.78.43.100
ns2.example.org. 7000 IN A 100.78.43.200
    "#;

    #[test]
    fn unanwsered_a_returns_ns_with_addrs() -> io::Result<()> {
        let zone = DnsZoneResolver::new(Zonefile::from_str(ZONEFILE_ORG)?)?;
        let respone = zone.query(DnsQuestion {
            qname: DnsString::new("www.example.org."),
            qclass: QuestionClass::IN,
            qtyp: QuestionTyp::A,
        });

        assert_eq!(respone.anwsers, []);
        assert_eq!(
            respone.auths,
            [
                NsResourceRecord {
                    domain: DnsString::new("example.org."),
                    ttl: 7000,
                    class: ResourceRecordClass::IN,
                    nameserver: DnsString::new("ns1.example.org."),
                }
                .into(),
                NsResourceRecord {
                    domain: DnsString::new("example.org."),
                    ttl: 7000,
                    class: ResourceRecordClass::IN,
                    nameserver: DnsString::new("ns2.example.org."),
                }
                .into()
            ]
        );
        assert_eq!(
            respone.additional,
            [
                AResourceRecord {
                    name: DnsString::new("ns1.example.org."),
                    ttl: 7000,
                    class: ResourceRecordClass::IN,
                    addr: Ipv4Addr::new(100, 78, 43, 100)
                }
                .into(),
                AResourceRecord {
                    name: DnsString::new("ns2.example.org."),
                    ttl: 7000,
                    class: ResourceRecordClass::IN,
                    addr: Ipv4Addr::new(100, 78, 43, 200)
                }
                .into()
            ]
        );
        Ok(())
    }

    const ZONEFILE_EXAMPLE_ORG: &str = r#"
example.org. 7000 IN SOA ns1.example.org. admin@example.org (7000 7000 7000 7000 7000)

example.org. 7000 IN NS ns1.example.org.

ns1.example.org. 1800 IN A 100.78.43.100

www.example.org.        1800 IN A 9.9.9.9
wwwtest.example.org.    1800 IN CNAME www.example.org.
testwwwtest.example.org 1800 IN CNAME wwwtest.example.org.
    "#;

    #[test]
    fn cname_resolved_to_addr() -> io::Result<()> {
        let zone = DnsZoneResolver::new(Zonefile::from_str(ZONEFILE_EXAMPLE_ORG)?)?;
        let respone = zone.query(DnsQuestion {
            qname: DnsString::new("wwwtest.example.org."),
            qclass: QuestionClass::IN,
            qtyp: QuestionTyp::A,
        });
        assert_eq!(
            respone.anwsers,
            [AResourceRecord {
                name: DnsString::new("www.example.org."),
                ttl: 1800,
                class: ResourceRecordClass::IN,
                addr: Ipv4Addr::new(9, 9, 9, 9)
            }
            .into(),]
        );

        Ok(())
    }

    #[test]
    fn cname_multi_step() -> io::Result<()> {
        let zone = DnsZoneResolver::new(Zonefile::from_str(ZONEFILE_EXAMPLE_ORG)?)?;
        let respone = zone.query(DnsQuestion {
            qname: DnsString::new("testwwwtest.example.org."),
            qclass: QuestionClass::IN,
            qtyp: QuestionTyp::A,
        });
        assert_eq!(
            respone.anwsers,
            [AResourceRecord {
                name: DnsString::new("www.example.org."),
                ttl: 1800,
                class: ResourceRecordClass::IN,
                addr: Ipv4Addr::new(9, 9, 9, 9)
            }
            .into(),]
        );

        Ok(())
    }
}
