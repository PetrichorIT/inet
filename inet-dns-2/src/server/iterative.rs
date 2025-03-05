use std::{mem, net::SocketAddr, sync::Arc};

use tracing::info_span;

use crate::{
    core::{DnsResourceRecord, Error, QueryResponse, Question, ResponseCode, ZoneResolver},
    server::transaction::{SourceQuery, TransactionResult},
};

use super::{
    transaction::FinishedTransaction, DnsMessage, Nameserver, NameserverQuery, TransportMedium,
};

/// Iterative authoritative nameserver managing multiple zones
/// and caching.
///
/// Can be used as a standalone nameserver or as a part of a larger system, e.g. a recursive nameserver.
#[derive(Debug)]
pub struct IterativeNameserver {
    authoratative: Vec<ZoneResolver>,
    cache: Option<ZoneResolver>,

    responses: Vec<FinishedTransaction>,
}

impl IterativeNameserver {
    /// Creates a new iterative nameserver with the given zones.
    pub fn new(mut zones: Vec<ZoneResolver>) -> Self {
        zones.sort_by_key(|resolver| resolver.zone().labels().len());
        Self {
            authoratative: zones,
            cache: None,
            responses: Vec::new(),
        }
    }

    /// Adds a cache to the nameserver. Entries in cache will be
    /// used only as a secondary source of information.
    pub fn with_cache(mut self) -> Self {
        self.cache = Some(ZoneResolver::cache());
        self
    }

    /// Adds a cached record to the nameserver.
    pub fn add_cached(&mut self, record: DnsResourceRecord) {
        if let Some(ref mut cache) = self.cache {
            cache.add_cached(record);
        }
    }

    /// Queries the nameserver for the given question.
    ///
    /// Returns a tuple containing a boolean indicating whether the response is authoritative,
    /// and the response itself.
    pub fn query(&self, question: &Question) -> Result<(bool, QueryResponse), Error> {
        // TODO: db tick

        tracing::debug!("{:?}", self.cache);

        let mut last_err = None;
        let mut last_delegate = None;

        for zone in self
            .authoratative
            .iter()
            .filter(|z| z.accepts_query(question))
        {
            match zone.query(question) {
                Ok(anwser) if !anwser.anwsers.is_empty() => return Ok((true, anwser)),
                Ok(delegate) => last_delegate = Some(delegate),
                Err(e) => last_err = Some(e),
            }
        }

        if let Some(ref cache) = self.cache {
            match cache.query(question) {
                Ok(anwser) if !anwser.anwsers.is_empty() => return Ok((false, anwser)),
                Ok(delegate) => last_delegate = Some(delegate),
                Err(e) => last_err = Some(e),
            }
        }

        last_delegate.map(|v| (false, v)).ok_or_else(|| {
            last_err.take().unwrap_or_else(|| {
                Error::new(ResponseCode::NotZone, "request directed to invalid zone")
            })
        })
    }
}

impl Nameserver for IterativeNameserver {
    fn tick(&mut self) {}

    fn incoming(&mut self, medium: TransportMedium, source: SocketAddr, msg: DnsMessage) {
        for question in msg.response.questions {
            let query = Arc::new(SourceQuery {
                medium,
                addr: source,
                transaction: msg.transaction,
                question,
            });

            info_span!("tx", query = %query).in_scope(|| {
                tracing::trace!("querying");
                match self.query(&query.question) {
                    Ok((authoratative, result)) => {
                        tracing::trace!("anwsered with:{}", result);
                        self.responses.push(FinishedTransaction {
                            query,
                            ra: false,
                            aa: authoratative,
                            result: TransactionResult::Success(result),
                        })
                    }
                    Err(error) => {
                        tracing::error!("query error: {error}");
                        self.responses.push(FinishedTransaction {
                            query,
                            ra: false,
                            aa: true,
                            result: TransactionResult::Failure(error),
                        });
                    }
                };
            });
        }
    }

    fn anwsers(&mut self) -> Vec<FinishedTransaction> {
        let mut vec = Vec::new();
        mem::swap(&mut vec, &mut self.responses);
        vec
    }

    fn ns_queries(&mut self) -> Vec<NameserverQuery> {
        Vec::new()
    }

    fn active_queries(&self) -> Vec<NameserverQuery> {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use std::{io, net::Ipv4Addr, str::FromStr};

    use super::*;
    use crate::core::{
        AResourceRecord, DnsString, Question, QuestionClass, QuestionTyp, ResourceRecordClass,
        Zonefile,
    };

    const ZONEFILE_ORG: &str = include_str!("../examples/org.zone");

    #[test]
    fn direct_anwser() -> io::Result<()> {
        let zone = ZoneResolver::new(Zonefile::from_str(ZONEFILE_ORG)?)?;
        let server = IterativeNameserver::new(vec![zone]);
        let question = Question {
            qname: "rss.info.org.".parse()?,
            qclass: QuestionClass::IN,
            qtyp: QuestionTyp::A,
        };
        let (_, response) = server.query(&question)?;
        assert_eq!(
            response.anwsers,
            [AResourceRecord {
                name: "rss.info.org.".parse()?,
                ttl: 7000,
                class: ResourceRecordClass::IN,
                addr: Ipv4Addr::new(100, 0, 0, 2)
            }
            .into()]
        );
        Ok(())
    }

    const ZONEFILE_EXAMPLE_ORG: &str = include_str!("../examples/example.org.zone");

    #[test]
    fn error_not_zone() -> io::Result<()> {
        let zone = ZoneResolver::new(Zonefile::from_str(ZONEFILE_ORG)?)?;
        let zone2 = ZoneResolver::new(Zonefile::from_str(ZONEFILE_EXAMPLE_ORG)?)?;
        let server = IterativeNameserver::new(vec![zone, zone2]);
        let question = Question {
            qname: "does-not-exist.org.".parse()?,
            qclass: QuestionClass::IN,
            qtyp: QuestionTyp::A,
        };
        let error = server.query(&question).expect_err("must be an error");
        assert_eq!(error.response_code(), ResponseCode::NxDomain);
        Ok(())
    }

    #[test]
    fn errors_propagated_to_transaction_finish() -> io::Result<()> {
        let zone = ZoneResolver::new(Zonefile::from_str(ZONEFILE_ORG)?)?;
        let mut server = IterativeNameserver::new(vec![zone]);
        let addr = "200.0.0.2:80".parse().unwrap();

        server.incoming(
            TransportMedium::Udp,
            addr,
            DnsMessage::question_a(1, "does-not-exist.org.".parse::<DnsString>()?),
        );

        let anwsers = server.anwsers();
        assert_eq!(
            anwsers,
            [FinishedTransaction {
                query: Arc::new(SourceQuery {
                    medium: TransportMedium::Udp,
                    addr,
                    transaction: 1,
                    question: Question {
                        qname: "does-not-exist.org.".parse()?,
                        qclass: QuestionClass::IN,
                        qtyp: QuestionTyp::A
                    },
                }),
                ra: false,
                aa: true,
                result: TransactionResult::Failure(Error::new(
                    ResponseCode::NxDomain,
                    "query could not be resolved"
                ))
            }]
        );

        Ok(())
    }

    const ZONEFILE_MISSING_ZONE: &str = include_str!("../examples/missing.zone");

    #[test]
    fn no_error_not_found_if_anweser_found_in_other_zone() -> io::Result<()> {
        let zone = ZoneResolver::new(Zonefile::from_str(ZONEFILE_ORG)?)?;
        let zone2 = ZoneResolver::new(Zonefile::from_str(ZONEFILE_MISSING_ZONE)?)?;
        let server = IterativeNameserver::new(vec![zone, zone2]);
        let question = Question {
            qname: "does-not-exist.org.".parse()?,
            qclass: QuestionClass::IN,
            qtyp: QuestionTyp::A,
        };
        let (_, response) = server.query(&question)?;
        assert_eq!(
            response.anwsers,
            [AResourceRecord {
                name: "does-not-exist.org.".parse()?,
                ttl: 1800,
                class: ResourceRecordClass::IN,
                addr: Ipv4Addr::new(192, 168, 2, 21)
            }
            .into()]
        );
        Ok(())
    }
}
