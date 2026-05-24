//! Base components to manage and query resource records (RR)

use des::time::SimTime;
use std::io;

mod db;
mod error;
mod question;
mod record;
mod response;
mod string;
mod zonefile;

pub use db::*;
pub use error::*;
pub use question::*;
pub use record::*;
pub use response::*;
pub use string::*;
pub use zonefile::*;

/// A zone resolver that manages and queries resource records (RR)
/// within one zone.
#[derive(Debug)]
pub struct ZoneResolver {
    db: RecordMap,
    zone: DnsString,
}

impl ZoneResolver {
    /// The zone this resolver is responsible for.
    pub fn zone(&self) -> &DnsString {
        &self.zone
    }

    /// Create a new resolver that caches records.
    #[must_use]
    pub fn cache() -> Self {
        Self {
            zone: DnsString::empty(),
            db: RecordMap::from_iter([]),
        }
    }

    /// Create a new resolver that loads records from a zonefile.
    ///
    /// # Errors
    ///
    /// Fails if no SOA entry is found.
    pub fn new(zf: Zonefile) -> io::Result<Self> {
        let db = zf.records.into_iter().collect::<RecordMap>();

        let soa = db
            .soa()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "no SOA entry"))?;
        Ok(Self {
            zone: soa.name().clone(),
            db,
        })
    }

    #[must_use]
    pub fn secondary(zone: DnsString) -> Self {
        Self {
            zone,
            db: RecordMap::from_iter([]),
        }
    }

    /// Check if this resolver accepts a query.
    pub fn accepts_query(&self, question: &Question) -> bool {
        question.qname.has_parent(&self.zone)
    }

    /// Add a record to the cache.
    pub fn add_cached(&mut self, record: DnsResourceRecord) {
        self.db.add(record, SimTime::now());
    }

    /// Returns all records in the cache.
    ///
    /// # Errors
    ///
    /// `Infallible`
    pub fn all(&self) -> Result<QueryResponse, Error> {
        let response = QueryResponse {
            questions: vec![Question {
                qname: self.zone.clone(),
                qtyp: QuestionTyp::AXFR,
                qclass: QuestionClass::IN,
            }],
            anwsers: self.db.all(),
            ..Default::default()
        };

        Ok(response)
    }

    /// Query the resolver for a given question. This will retrieve
    /// all RRs that match the query, including dependent queries
    /// that can be derived from the original query.
    ///
    /// # Errors
    ///
    /// Fails if the query cannot be anwsered.
    pub fn query(&self, question: &Question) -> Result<QueryResponse, Error> {
        if !question.qname.has_parent(&self.zone) {
            return Err(Error::new(
                ResponseCode::NotZone,
                "question was directed at wrong zone".to_string(),
            ));
        }

        let question = question.mutate_query(self);
        self.query_inner(question)
    }

    fn query_inner(&self, question: Question) -> Result<QueryResponse, Error> {
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
                    break;
                }
            }

            if response.is_reponse_empty() {
                return Err(Error::new(
                    ResponseCode::NxDomain,
                    format!("query '{question}' could not be resolved"),
                ));
            }
        } else {
            response.anwsers.extend(results.iter().cloned());
            for (additional, kind) in question.on_anwsered(results) {
                response.include(self.db.query(&additional), kind);
            }
        }

        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::{net::Ipv4Addr, str::FromStr};

    const ZONEFILE_ORG: &str = include_str!("../examples/org.zone");

    #[test]
    fn query_can_be_anwsered_directly() -> io::Result<()> {
        let zone = ZoneResolver::new(Zonefile::from_str(ZONEFILE_ORG)?)?;
        let response = zone.query(&Question {
            qname: "info.org.".parse()?,
            qclass: QuestionClass::IN,
            qtyp: QuestionTyp::A,
        })?;

        assert_eq!(
            response.anwsers,
            [AResourceRecord {
                name: "info.org.".parse()?,
                ttl: 7000,
                class: ResourceRecordClass::IN,
                addr: Ipv4Addr::new(100, 0, 0, 1),
            }
            .into()]
        );
        assert_eq!(response.auths, []);
        assert_eq!(
            response.additional,
            [AAAAResourceRecord {
                name: "info.org.".parse()?,
                ttl: 7000,
                class: ResourceRecordClass::IN,
                addr: "fc00:db20:35b:7399::5".parse().unwrap(),
            }
            .into()]
        );

        Ok(())
    }

    #[test]
    fn query_in_deeper_level_can_be_anwesered_directly() -> io::Result<()> {
        let zone = ZoneResolver::new(Zonefile::from_str(ZONEFILE_ORG)?)?;
        let response = zone.query(&Question {
            qname: "rss.info.org.".parse()?,
            qclass: QuestionClass::IN,
            qtyp: QuestionTyp::A,
        })?;

        assert_eq!(
            response.anwsers,
            [AResourceRecord {
                name: "rss.info.org.".parse()?,
                ttl: 7000,
                class: ResourceRecordClass::IN,
                addr: Ipv4Addr::new(100, 0, 0, 2),
            }
            .into()]
        );
        assert_eq!(response.auths, []);
        assert_eq!(response.additional, []);

        Ok(())
    }

    #[test]
    fn query_can_delegate_to_ns_authority() -> io::Result<()> {
        let zone = ZoneResolver::new(Zonefile::from_str(ZONEFILE_ORG)?)?;
        let respone = zone.query(&Question {
            qname: "www.example.org.".parse()?,
            qclass: QuestionClass::IN,
            qtyp: QuestionTyp::A,
        })?;

        assert_eq!(respone.anwsers, []);
        assert_eq!(
            respone.auths,
            [NsResourceRecord {
                domain: "example.org.".parse()?,
                ttl: 7000,
                class: ResourceRecordClass::IN,
                nameserver: "ns1.example.org.".parse()?,
            }
            .into()]
        );
        assert_eq!(
            respone.additional,
            [AResourceRecord {
                name: "ns1.example.org.".parse()?,
                ttl: 7000,
                class: ResourceRecordClass::IN,
                addr: Ipv4Addr::new(192, 168, 2, 30)
            }
            .into(),]
        );
        Ok(())
    }

    #[test]
    fn error_no_such_name() -> io::Result<()> {
        let zone = ZoneResolver::new(Zonefile::from_str(ZONEFILE_ORG)?)?;
        let response = zone
            .query(&Question {
                qname: "www.does-not-exist.org.".parse()?,
                qclass: QuestionClass::IN,
                qtyp: QuestionTyp::A,
            })
            .expect_err("query must result in error, since neither anwsers nor auths can exist");

        assert_eq!(response.response_code(), ResponseCode::NxDomain);
        Ok(())
    }

    #[test]
    fn error_not_zone() -> io::Result<()> {
        let zone = ZoneResolver::new(Zonefile::from_str(ZONEFILE_ORG)?)?;
        let response = zone
            .query(&Question {
                qname: "www.does-not-exist.net.".parse()?,
                qclass: QuestionClass::IN,
                qtyp: QuestionTyp::A,
            })
            .expect_err("query must result in error, since neither anwsers nor auths can exist");

        assert_eq!(response.response_code(), ResponseCode::NotZone);
        Ok(())
    }

    const ZONEFILE_EXAMPLE_ORG: &str = include_str!("../examples/example.org.zone");

    #[test]
    fn cname_resolved_to_addr() -> io::Result<()> {
        let zone = ZoneResolver::new(Zonefile::from_str(ZONEFILE_EXAMPLE_ORG)?)?;
        let respone = zone
            .query(&Question {
                qname: DnsString::from_str("www.example.org.")?,
                qclass: QuestionClass::IN,
                qtyp: QuestionTyp::A,
            })
            .unwrap();
        assert_eq!(
            respone.anwsers,
            [AResourceRecord {
                name: DnsString::from_str("alice.example.org.")?,
                ttl: 1800,
                class: ResourceRecordClass::IN,
                addr: Ipv4Addr::new(192, 168, 0, 101)
            }
            .into(),]
        );

        Ok(())
    }

    #[test]
    fn cname_multi_step() -> io::Result<()> {
        let zone = ZoneResolver::new(Zonefile::from_str(ZONEFILE_EXAMPLE_ORG)?)?;
        let respone = zone
            .query(&Question {
                qname: DnsString::from_str("wwwalice.example.org.")?,
                qclass: QuestionClass::IN,
                qtyp: QuestionTyp::A,
            })
            .unwrap();
        assert_eq!(
            respone.anwsers,
            [AResourceRecord {
                name: DnsString::from_str("alice.example.org.")?,
                ttl: 1800,
                class: ResourceRecordClass::IN,
                addr: Ipv4Addr::new(192, 168, 0, 101)
            }
            .into(),]
        );

        Ok(())
    }

    #[test]
    fn multi_authorative_referall() -> io::Result<()> {
        let zone = ZoneResolver::new(Zonefile::from_str(ZONEFILE_EXAMPLE_ORG)?)?;
        let response = zone
            .query(&Question {
                qname: DnsString::from_str("www.subdomain.example.org.")?,
                qclass: QuestionClass::IN,
                qtyp: QuestionTyp::A,
            })
            .unwrap();
        assert_eq!(response.auths.len(), 2, "was {:#?}", response);
        assert_eq!(response.additional.len(), 3, "was {:#?}", response);
        Ok(())
    }
}
