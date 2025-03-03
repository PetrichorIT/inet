use std::net::SocketAddr;

use tracing::info_span;

use crate::{
    core::{DnsResourceRecord, Error, QueryResponse, Question, ResponseCode, ZoneResolver},
    server::transaction::TransactionResult,
};

use super::{transaction::FinishedTransaction, types::NameserverQuery, DnsMessage, Nameserver};

pub struct IterativeNameserver {
    zones: Vec<ZoneResolver>,
    cache: Option<ZoneResolver>,

    responses: Vec<FinishedTransaction>,
}

impl IterativeNameserver {
    pub fn new(mut zones: Vec<ZoneResolver>) -> Self {
        zones.sort_by_key(|resolver| resolver.zone().labels().len());
        Self {
            zones,
            cache: None,
            responses: Vec::new(),
        }
    }

    pub fn with_cache(mut self) -> Self {
        self.cache = Some(ZoneResolver::cache());
        self
    }

    pub fn add_cached(&mut self, record: DnsResourceRecord) {
        if let Some(ref mut cache) = self.cache {
            cache.add_cached(record);
        }
    }

    pub fn query(&self, question: &Question) -> Result<QueryResponse, Error> {
        // TODO: db tick

        let mut last_err = None;
        for zone in self
            .zones
            .iter()
            .chain(self.cache.iter())
            .filter(|z| z.accepts_query(question))
            .rev()
        {
            match zone.query(question) {
                Ok(anwser) => return Ok(anwser),
                Err(e) => last_err = Some(e),
            }
        }

        Err(last_err.take().unwrap_or_else(|| {
            Error::new(ResponseCode::NotZone, "request directed to invalid zone")
        }))
    }
}

impl Nameserver for IterativeNameserver {
    fn incoming(&mut self, source: SocketAddr, msg: DnsMessage) {
        info_span!("tx", req = msg.transaction).in_scope(|| {
            for question in msg.response.questions {
                tracing::trace!("querying '{}'", question);
                match self.query(&question) {
                    Ok(result) => self.responses.push(FinishedTransaction {
                        transaction: msg.transaction,
                        result: TransactionResult::Success(result),
                        question,
                        client: source,
                    }),
                    Err(error) => {
                        tracing::error!("query error: {error}");
                        self.responses.push(FinishedTransaction {
                            transaction: msg.transaction,
                            result: TransactionResult::Failure(error),
                            question,
                            client: source,
                        });
                        return;
                    }
                };
            }
        });
    }

    fn anwsers(&mut self) -> impl Iterator<Item = FinishedTransaction> {
        self.responses.drain(..).map(|v| {
            tracing::trace!("responding to '{}' with:{}", v.question, v.result);
            v
        })
    }

    fn queries(&mut self) -> impl Iterator<Item = NameserverQuery> {
        std::iter::empty()
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
        let response = server.query(&question)?;
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
            addr,
            DnsMessage::question_a(1, "does-not-exist.org.".parse::<DnsString>()?),
        );

        let anwsers = server.anwsers().collect::<Vec<_>>();
        assert_eq!(
            anwsers,
            [FinishedTransaction {
                transaction: 1,
                client: addr,
                question: Question {
                    qname: "does-not-exist.org.".parse()?,
                    qclass: QuestionClass::IN,
                    qtyp: QuestionTyp::A
                },
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
        let response = server.query(&question)?;
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
