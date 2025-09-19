use std::{
    mem,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicU16, Ordering},
    },
    time::Duration,
};

use des::time::SimTime;
use tracing::info_span;

use crate::{
    core::{
        DnsString, Error, QueryResponse, Question, QuestionClass, QuestionTyp, ResponseCode,
        ZoneResolver, Zonefile,
    },
    server::transaction::{SourceQuery, TransactionResult},
};

use super::{
    DnsMessage, Nameserver, NameserverQuery, TransportMedium, transaction::FinishedTransaction,
};

/// Iterative authoritative nameserver managing multiple zones
/// and caching.
///
/// Can be used as a standalone nameserver or as a part of a larger system, e.g. a recursive nameserver.
#[derive(Debug)]
pub struct IterativeNameserver {
    authoratative: Vec<ZoneResolver>,
    role: Role,
    tx_id: AtomicU16,

    axfr_queries: Vec<NameserverQuery>,
    responses: Vec<FinishedTransaction>,
}

#[derive(Debug, Clone)]
pub enum Role {
    Primary,
    Secondary {
        primary: IpAddr,
        next_update: SimTime,
        active: Vec<NameserverQuery>,
    },
}

impl IterativeNameserver {
    /// Creates a new iterative nameserver with the given zones.
    pub fn primary(mut zones: Vec<ZoneResolver>) -> Self {
        zones.sort_by_key(|resolver| resolver.zone().labels().len());
        Self {
            authoratative: zones,
            role: Role::Primary,
            tx_id: AtomicU16::new(0),

            responses: Vec::new(),
            axfr_queries: Vec::new(),
        }
    }

    pub fn secondary(zones: Vec<DnsString>, ip: IpAddr) -> Self {
        let zones = zones
            .into_iter()
            .map(ZoneResolver::secondary)
            .collect::<Vec<_>>();

        Self {
            authoratative: zones,
            role: Role::Secondary {
                primary: ip,
                next_update: SimTime::ZERO,
                active: Vec::new(),
            },
            tx_id: AtomicU16::new(0),

            responses: Vec::new(),
            axfr_queries: Vec::new(),
        }
    }

    /// Queries the nameserver for the given question.
    ///
    /// Returns a tuple containing a boolean indicating whether the response is authoritative,
    /// and the response itself.
    pub fn query(&self, question: &Question) -> Result<QueryResponse, Error> {
        if let QuestionTyp::AXFR = question.qtyp {
            if let Role::Secondary { .. } = self.role {
                return Err(Error::new(ResponseCode::NotAuth, "no auth primary"));
            }

            return if let Some(zone) = self
                .authoratative
                .iter()
                .find(|zone| zone.zone() == &question.qname)
            {
                zone.all()
            } else {
                Err(Error::new(ResponseCode::NotZone, "no auth zone"))
            };
        }

        let mut last_err = None;
        let mut last_delegate = None;

        for zone in self
            .authoratative
            .iter()
            .filter(|z| z.accepts_query(question))
        {
            match zone.query(question) {
                Ok(anwser) if !anwser.anwsers.is_empty() => return Ok(anwser),
                Ok(delegate) => last_delegate = Some(delegate),
                Err(e) => last_err = Some(e),
            }
        }

        last_delegate.ok_or_else(|| {
            last_err.take().unwrap_or_else(|| {
                Error::new(ResponseCode::NotZone, "request directed to invalid zone")
            })
        })
    }

    fn on_request(&mut self, medium: TransportMedium, source: SocketAddr, msg: DnsMessage) {
        let edns = msg.edns().cloned();
        for question in msg.response.questions {
            let query = Arc::new(SourceQuery {
                medium,
                edns: edns.clone(),
                addr: source,
                transaction: msg.transaction,
                question,
            });

            info_span!("tx", query = %query).in_scope(|| {
                tracing::trace!("querying");

                // for AXFR queries, we need to use TCP
                if query.question.qtyp == QuestionTyp::AXFR && query.medium != TransportMedium::Tcp
                {
                    self.responses.push(FinishedTransaction {
                        query,
                        ra: false,
                        aa: false,
                        result: TransactionResult::Failure(Error::new(
                            ResponseCode::BadMode,
                            "AXFR over non TCP",
                        )),
                    });
                    return;
                }

                match self.query(&query.question) {
                    Ok(result) => {
                        tracing::trace!("anwsered with:{}", result);
                        self.responses.push(FinishedTransaction {
                            query,
                            ra: false,
                            aa: true,
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

    fn on_response(&mut self, medium: TransportMedium, source: SocketAddr, msg: DnsMessage) {
        // only AXFR response are valid
        let Some(question) = msg.response.questions.first() else {
            return;
        };

        if question.qtyp != QuestionTyp::AXFR {
            return;
        }

        let Role::Secondary {
            primary, active, ..
        } = &mut self.role
        else {
            return;
        };

        assert_eq!(medium, TransportMedium::Tcp);
        assert_eq!(source.ip(), *primary);

        let Some(zone) = self
            .authoratative
            .iter_mut()
            .find(|z| z.zone() == &question.qname)
        else {
            return;
        };

        let Some(i) = active.iter().position(|z| z.nameserver_ip == source.ip()) else {
            return;
        };
        active.remove(i);

        tracing::trace!("rewriting secondary auth zone '{}'", zone.zone());
        *zone = ZoneResolver::new(Zonefile {
            records: msg.response.anwsers,
        })
        .expect("failed to encode");
    }
}

impl Nameserver for IterativeNameserver {
    fn tick(&mut self) {
        if let Role::Secondary {
            primary,
            next_update,
            active,
        } = &mut self.role
            && *next_update <= SimTime::now()
        {
            tracing::trace!("requesting updates for all auth zones");

            for zone in &self.authoratative {
                let query = NameserverQuery {
                    query: Arc::new(SourceQuery {
                        medium: TransportMedium::Tcp,
                        edns: None, // TCP does not require EDNS

                        addr: SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0),
                        transaction: 0,
                        question: Question {
                            qname: zone.zone().clone(),
                            qclass: QuestionClass::IN,
                            qtyp: QuestionTyp::AXFR,
                        },
                    }),
                    preferred: Some(TransportMedium::Tcp),
                    nameserver_ip: *primary,
                    transaction: self.tx_id.fetch_add(1, Ordering::Relaxed),
                };

                active.push(query.clone());
                self.axfr_queries.push(query);
            }

            *next_update = SimTime::now() + Duration::from_secs(3600);
        }
    }

    fn incoming(&mut self, medium: TransportMedium, source: SocketAddr, msg: DnsMessage) {
        if msg.qr {
            self.on_response(medium, source, msg);
        } else {
            self.on_request(medium, source, msg);
        }
    }

    fn anwsers(&mut self) -> Vec<FinishedTransaction> {
        let mut vec = Vec::new();
        mem::swap(&mut vec, &mut self.responses);
        vec
    }

    fn ns_queries(&mut self) -> Vec<NameserverQuery> {
        let mut vec = Vec::new();
        mem::swap(&mut vec, &mut self.axfr_queries);
        vec
    }

    fn active_queries(&self) -> Vec<NameserverQuery> {
        if let Role::Secondary { active, .. } = &self.role {
            active.clone()
        } else {
            Vec::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashSet, io, net::Ipv4Addr, str::FromStr, time::Duration};

    use bytes_io::{FromBytes, ToBytes};
    use des::time::sleep;
    use inet::{UdpSocket, dns::ToSocketAddrs, test_util::SimpleSim};
    use serial_test::serial;

    use super::*;
    use crate::{
        adapters::{Base, TcpAdapter, UdpAdapter},
        core::{
            AResourceRecord, DnsResourceRecord, DnsString, Question, QuestionClass, QuestionTyp,
            ResourceRecordClass, Zonefile,
        },
    };

    const ZONEFILE_ORG: &str = include_str!("../examples/org.zone");

    #[test]
    fn direct_anwser() -> io::Result<()> {
        let zone = ZoneResolver::new(Zonefile::from_str(ZONEFILE_ORG)?)?;
        let server = IterativeNameserver::primary(vec![zone]);
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
        let server = IterativeNameserver::primary(vec![zone, zone2]);
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
        let mut server = IterativeNameserver::primary(vec![zone]);
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
                    edns: None,

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
        let server = IterativeNameserver::primary(vec![zone, zone2]);
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

    // # AXFR

    #[test]
    fn axfr_request() -> io::Result<()> {
        let zf = Zonefile::from_str(ZONEFILE_ORG)?;
        let zone = ZoneResolver::new(zf.clone())?;
        let server = IterativeNameserver::primary(vec![zone]);
        let question = Question {
            qname: "org.".parse()?,
            qclass: QuestionClass::IN,
            qtyp: QuestionTyp::AXFR,
        };
        let response = server.query(&question)?;
        assert_eq!(
            response
                .anwsers
                .iter()
                .map(DnsResourceRecord::as_raw)
                .collect::<HashSet<_>>(),
            zf.records
                .iter()
                .map(DnsResourceRecord::as_raw)
                .collect::<HashSet<_>>(),
        );
        Ok(())
    }

    #[test]
    fn axfr_deny_over_non_tcp() -> io::Result<()> {
        let zf = Zonefile::from_str(ZONEFILE_ORG)?;
        let zone = ZoneResolver::new(zf)?;
        let mut server = IterativeNameserver::primary(vec![zone]);
        let question = Question {
            qname: "org.".parse()?,
            qclass: QuestionClass::IN,
            qtyp: QuestionTyp::AXFR,
        };
        server.incoming(
            TransportMedium::Udp,
            SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 53),
            DnsMessage::query(1, question),
        );

        let resp = DnsMessage::response_from_transaction(server.anwsers().remove(0));
        assert_eq!(resp.rcode, ResponseCode::BadMode);
        Ok(())
    }

    const ZONEFILE_COM: &str = include_str!("../examples/com.zone");

    #[test]
    #[serial]
    fn axfr_secondary_server_queries_primary() {
        let mut sim = SimpleSim::new(inet::init);
        sim.node("192.168.2.10", || async move {
            let zf1 = ZoneResolver::new(Zonefile::from_str(ZONEFILE_ORG)?)?;
            let zf2 = ZoneResolver::new(Zonefile::from_str(ZONEFILE_EXAMPLE_ORG)?)?;
            let zf3 = ZoneResolver::new(Zonefile::from_str(ZONEFILE_COM)?)?;
            let auth = IterativeNameserver::primary(vec![zf1, zf2, zf3]);
            Base::new(auth)
                .with_adapter(TransportMedium::Udp, UdpAdapter::default())
                .with_adapter(TransportMedium::Tcp, TcpAdapter::default())
                .deploy()
                .await
        });

        sim.node("192.168.2.11", || async move {
            let auth = IterativeNameserver::secondary(
                vec!["org.".parse()?, "com.".parse()?],
                Ipv4Addr::new(192, 168, 2, 10).into(),
            );
            Base::new(auth)
                .with_adapter(TransportMedium::Udp, UdpAdapter::default())
                .with_adapter(TransportMedium::Tcp, TcpAdapter::default())
                .deploy()
                .await
        });

        sim.node_require_join("192.168.2.101", || async move {
            sleep(Duration::from_secs(5)).await;

            let rssorg = simple_udp_query(1, "rss.info.org.", "192.168.2.11:53").await?;
            assert_eq!(rssorg.response.anwsers.len(), 1);

            let rsscom = simple_udp_query(1, "rss.info.com.", "192.168.2.11:53").await?;
            assert_eq!(rsscom.response.anwsers.len(), 1);

            let aliceorg = simple_udp_query(1, "alice.example.org.", "192.168.2.11:53").await?;
            assert_eq!(aliceorg.response.anwsers.len(), 0);
            assert_eq!(aliceorg.response.auths.len(), 1);

            Ok(())
        });

        let _ = sim.run();
    }

    async fn simple_udp_query(
        tx: u16,
        name: &str,
        addr: impl ToSocketAddrs,
    ) -> io::Result<DnsMessage> {
        let udp = UdpSocket::bind("0.0.0.0:0").await?;
        udp.send_to(
            &DnsMessage::question_a(tx, name.parse()?).write_to_bytes_mut()?,
            addr,
        )
        .await?;

        let mut buf = vec![0u8; 512];
        let (len, _) = udp.recv_from(&mut buf).await?;
        let resp = DnsMessage::peek_from(&buf[..len])?;

        Ok(resp)
    }
}
