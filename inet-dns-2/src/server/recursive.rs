use std::{
    io, mem,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use des::{
    runtime::{self, random},
    time::SimTime,
};
use rand::seq::SliceRandom;
use tracing::info_span;

use crate::{
    core::{
        AAAAResourceRecord, AResourceRecord, DnsString, Error, NsResourceRecord, Question,
        QuestionClass, QuestionTyp, ResourceRecordClass, ResourceRecordTyp, ResponseCode,
        ZoneResolver, Zonefile,
    },
    server::transaction::TransactionResult,
};

use super::{
    iterative::IterativeNameserver,
    transaction::{ActiveTransaction, FinishedTransaction, SourceQuery},
    DnsMessage, Nameserver, NameserverQuery, TransportMedium,
};

/// A recursive nameserver.
///
/// This nameserver is responsible for resolving DNS queries recursively, starting from the root
/// nameservers and following the chain of referrals until the final answer is obtained.
#[derive(Debug)]
pub struct RecursiveNameserver {
    pub inner: IterativeNameserver,

    pub roots: Vec<(IpAddr, String)>,

    pub active_transactions: Vec<ActiveTransaction>,
    pub transaction_num: u16,

    // trait out
    pub queries: Vec<NameserverQuery>,
    pub finished_transactions: Vec<FinishedTransaction>,
}

impl RecursiveNameserver {
    /// Creates a new recursive nameserver.
    pub fn new(zone: Zonefile) -> io::Result<Self> {
        Ok(Self {
            inner: IterativeNameserver::new(vec![ZoneResolver::new(zone)?]).with_cache(),

            queries: Vec::new(),
            roots: Vec::new(),

            active_transactions: Vec::new(),
            finished_transactions: Vec::new(),
            transaction_num: 1,
        })
    }

    /// Adds a list of root nameservers to the recursive nameserver.
    pub fn with_roots(mut self, roots: Vec<(IpAddr, String)>) -> Self {
        self.roots = roots;
        self
    }

    fn on_incoming_query_request(&mut self, query: SourceQuery) {
        let tx = ActiveTransaction {
            query: Arc::new(query),

            local_transaction: self.transaction_num,
            remote: Vec::new(),
            deadline: SimTime::now() + Duration::from_secs(2),
            operation_counter: 0,
        };
        self.transaction_num += 1;
        info_span!("tx", query = %tx.query).in_scope(|| self.on_query_request(tx));
    }

    fn get_addr_of(&self, domain: &DnsString) -> Option<IpAddr> {
        let (_, response) = self
            .inner
            .query(&Question {
                qname: domain.clone(),
                qclass: QuestionClass::IN,
                qtyp: QuestionTyp::A,
            })
            .ok()?;

        if response.anwsers.is_empty() {
            None
        } else {
            let record = &response.anwsers[random::<usize>() % response.anwsers.len()];
            match record.typ() {
                ResourceRecordTyp::A => Some(
                    record
                        .as_any()
                        .downcast_ref::<AResourceRecord>()
                        .unwrap()
                        .addr
                        .into(),
                ),
                ResourceRecordTyp::AAAA => Some(
                    record
                        .as_any()
                        .downcast_ref::<AAAAResourceRecord>()
                        .unwrap()
                        .addr
                        .into(),
                ),
                _ => None,
            }
        }
    }

    fn on_query_request(&mut self, mut tx: ActiveTransaction) {
        tracing::trace!("querying");
        tx.operation_counter += 1;
        match self.inner.query(&tx.query.question) {
            Ok((authoratative, resp)) => {
                // Direct anwser
                if !resp.anwsers.is_empty() {
                    tracing::trace!(
                        "anwsered with {} anwsers: \n{}",
                        resp.anwsers.len(),
                        resp.anwsers[0]
                    );
                    self.finished_transactions.push(FinishedTransaction {
                        query: tx.query.clone(),
                        ra: true,
                        aa: authoratative,
                        result: TransactionResult::Success(resp),
                    });
                    return;
                }

                // Referral to other NS
                if !resp.auths.is_empty() {
                    let mut nameservers = resp
                        .auths
                        .iter()
                        .map(|rr| {
                            rr.as_any()
                                .downcast_ref::<NsResourceRecord>()
                                .expect("auths must be NS record")
                                .clone()
                        })
                        .filter_map(|ns| {
                            let ns_addr = self.get_addr_of(&ns.nameserver)?;
                            Some((ns, ns_addr))
                        })
                        .collect::<Vec<_>>();
                    nameservers.shuffle(runtime::rng());

                    let (ns, ns_addr) = &nameservers[0];

                    tracing::trace!("delegating to {} ({})", ns.nameserver, ns_addr);

                    self.queries.push(NameserverQuery {
                        transaction: tx.local_transaction,
                        nameserver_ip: *ns_addr,
                        query: tx.query.clone(),
                    });

                    tx.remote = nameservers;
                    assert!(!tx.remote.is_empty());
                    self.active_transactions.push(tx);

                    return;
                }

                unreachable!("no anwsers, no auths would result in NxDomain")
            }
            Err(e) if e.response_code() == ResponseCode::NxDomain => {
                if self.roots.is_empty() {
                    tracing::error!("no root nameserver available");
                    self.finished_transactions.push(FinishedTransaction {
                        query: tx.query.clone(),
                        ra: true,
                        aa: true,
                        result: TransactionResult::Failure(Error::new(ResponseCode::NxDomain, "")),
                    });
                    return;
                }

                let root = &self.roots[random::<usize>() % self.roots.len()];
                self.queries.push(NameserverQuery {
                    transaction: tx.local_transaction,
                    nameserver_ip: root.0,
                    query: tx.query.clone(),
                });
                tracing::trace!("delegating to root nameserver {:?} ", root);

                tx.remote = vec![(
                    NsResourceRecord {
                        domain: DnsString::empty(),
                        ttl: 7000,
                        class: ResourceRecordClass::IN, // TODO: make tx dependen
                        nameserver: DnsString::empty(),
                    },
                    root.0,
                )];

                self.active_transactions.push(tx);
            }

            Err(e) => {
                tracing::error!("internal: {e}")
            }
        }
    }

    fn on_query_response(&mut self, _source: SocketAddr, msg: DnsMessage) {
        let Some(active_transaction_idx) = self
            .active_transactions
            .iter()
            .position(|t| t.local_transaction == msg.transaction)
        else {
            return;
        };

        let tx = self.active_transactions.remove(active_transaction_idx);

        info_span!("tx", query = %tx.query).in_scope(|| {
            if msg.rcode != ResponseCode::NoError {
                tracing::warn!("got response with errors {:?}", msg.rcode);
                self.finished_transactions.push(FinishedTransaction {
                    ra: true,
                    aa: false,
                    query: tx.query.clone(),
                    result: TransactionResult::Failure(Error::new(msg.rcode, "")),
                });
                return;
            }

            tracing::trace!("got response: {} elements", msg.response().count());

            for record in msg.response() {
                self.inner.add_cached(record.clone());
            }

            //  Restate questions
            self.on_query_request(tx);
        });
    }

    fn on_query_failure(&mut self, mut tx: ActiveTransaction) {
        info_span!("tx", query = %tx.query).in_scope(|| {
            tx.local_transaction += 1;
            tx.operation_counter += 1;

            tx.remote.remove(0);

            if tx.remote.is_empty() {
                self.finished_transactions.push(FinishedTransaction {
                    query: tx.query.clone(),
                    ra: true,
                    aa: false,
                    result: TransactionResult::Failure(Error::new(ResponseCode::NxDomain, "")),
                });
            } else {
                let (ns, ns_addr) = &tx.remote[0];

                tracing::trace!("delegating to fallback {} ({})", ns.nameserver, ns_addr);

                self.queries.push(NameserverQuery {
                    transaction: tx.local_transaction,
                    nameserver_ip: *ns_addr,
                    query: tx.query.clone(),
                });
                self.active_transactions.push(tx);
            }
        });
    }
}

impl Nameserver for RecursiveNameserver {
    fn tick(&mut self) {
        let now = SimTime::now();

        let expired: Vec<ActiveTransaction>;
        (expired, self.active_transactions) = self
            .active_transactions
            .iter()
            .cloned()
            .partition(|tx| tx.deadline <= now);

        for tx in expired {
            self.on_query_failure(tx);
        }
    }

    fn incoming(&mut self, medium: TransportMedium, addr: SocketAddr, msg: DnsMessage) {
        if msg.qr {
            self.on_query_response(addr, msg);
        } else {
            for question in &msg.response.questions {
                let query = SourceQuery {
                    medium,
                    addr,
                    transaction: msg.transaction,
                    question: question.clone(),
                };
                if msg.rd {
                    // dispatch to recursive resolver
                    self.on_incoming_query_request(query);
                } else {
                    // use default iterative resolver
                    let query = Arc::new(query);
                    info_span!("tx", query = %query).in_scope(|| {
                        tracing::trace!("querying");
                        match self.inner.query(&query.question) {
                            Ok((authoratative, result)) => {
                                tracing::trace!("anwsered with:{}", result);
                                self.finished_transactions.push(FinishedTransaction {
                                    query,
                                    ra: false,
                                    aa: authoratative,
                                    result: TransactionResult::Success(result),
                                })
                            }
                            Err(error) => {
                                tracing::error!("query error: {error}");
                                self.finished_transactions.push(FinishedTransaction {
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
        }
    }

    fn anwsers(&mut self) -> Vec<FinishedTransaction> {
        let mut vec = Vec::new();
        mem::swap(&mut vec, &mut self.finished_transactions);
        vec
    }

    fn ns_queries(&mut self) -> Vec<NameserverQuery> {
        let mut vec = Vec::new();
        mem::swap(&mut vec, &mut self.queries);
        vec
    }

    fn active_queries(&self) -> Vec<NameserverQuery> {
        self.active_transactions
            .iter()
            .filter(|tx| !tx.remote.is_empty())
            .map(|tx| NameserverQuery {
                nameserver_ip: tx.remote[0].1,
                transaction: tx.local_transaction,
                query: tx.query.clone(),
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use std::{net::Ipv4Addr, str::FromStr};

    use des::{
        net::{AsyncFn, Sim},
        runtime::Builder,
        time::sleep,
    };
    use serial_test::serial;

    use crate::{
        core::{Error, QueryResponse, ResourceRecordClass},
        server::OpCode,
    };

    use super::*;

    const ZONEFILE_ORG: &str = include_str!("../examples/org.zone");

    #[test]
    #[serial]
    fn referral_anwser_finishes_transaction() {
        let mut sim = Sim::new(()).with_stack(inet::init);
        sim.node(
            "alice",
            AsyncFn::io(|_| async move {
                let zone = Zonefile::from_str(ZONEFILE_ORG)?;
                let mut server = RecursiveNameserver::new(zone)?;

                let addr = "2.2.2.2:2".parse().unwrap();
                server.incoming(
                    TransportMedium::Udp,
                    addr,
                    DnsMessage::question_a(1, "alice.example.org.".parse::<DnsString>()?),
                );

                let question = Question {
                    qname: "alice.example.org.".parse()?,
                    qclass: QuestionClass::IN,
                    qtyp: QuestionTyp::A,
                };
                let query = Arc::new(SourceQuery {
                    medium: TransportMedium::Udp,
                    question: question.clone(),
                    transaction: 1,
                    addr,
                });

                let nsaddr = Ipv4Addr::new(192, 168, 2, 30).into();

                assert_eq!(server.anwsers(), []);
                assert_eq!(
                    server.ns_queries(),
                    [NameserverQuery {
                        nameserver_ip: nsaddr,
                        transaction: 1,
                        query: query.clone()
                    }]
                );

                let resp = QueryResponse {
                    questions: vec![question.clone()],
                    anwsers: vec![AResourceRecord {
                        name: "alice.example.org.".parse()?,
                        ttl: 7000,
                        class: ResourceRecordClass::IN,
                        addr: Ipv4Addr::new(1, 2, 3, 4),
                    }
                    .into()],
                    ..Default::default()
                };
                server.incoming(
                    TransportMedium::Udp,
                    SocketAddr::new(nsaddr, 43),
                    DnsMessage {
                        transaction: 1,
                        qr: true,
                        ra: false,
                        rd: false,
                        aa: false,
                        tc: false,
                        opcode: OpCode::Query,
                        rcode: ResponseCode::NoError,
                        response: resp.clone(),
                    },
                );

                assert_eq!(
                    server.anwsers(),
                    [FinishedTransaction {
                        query,
                        ra: true,
                        aa: false,
                        result: TransactionResult::Success(resp)
                    }]
                );
                assert_eq!(server.ns_queries(), []);

                Ok(())
            }),
        );
        let _ = Builder::seeded(123).max_time(100.0.into()).build(sim).run();
    }

    #[test]
    #[serial]
    fn referred_error_will_be_propagated() {
        let mut sim = Sim::new(()).with_stack(inet::init);
        sim.node(
            "alice",
            AsyncFn::io(|_| async move {
                let zone = Zonefile::from_str(ZONEFILE_ORG)?;
                let mut server = RecursiveNameserver::new(zone)?;

                let addr = "2.2.2.2:2".parse().unwrap();
                server.incoming(
                    TransportMedium::Udp,
                    addr,
                    DnsMessage::question_a(1, "alice.example.org.".parse::<DnsString>()?),
                );

                let question = Question {
                    qname: "alice.example.org.".parse()?,
                    qclass: QuestionClass::IN,
                    qtyp: QuestionTyp::A,
                };
                let query = Arc::new(SourceQuery {
                    medium: TransportMedium::Udp,
                    question: question.clone(),
                    transaction: 1,
                    addr,
                });

                let nsaddr = Ipv4Addr::new(192, 168, 2, 30).into();

                assert_eq!(server.anwsers(), []);
                assert_eq!(
                    server.ns_queries(),
                    [NameserverQuery {
                        nameserver_ip: nsaddr,
                        transaction: 1,
                        query: query.clone()
                    }]
                );

                server.incoming(
                    TransportMedium::Udp,
                    SocketAddr::new(nsaddr, 43),
                    DnsMessage::response_from_transaction(FinishedTransaction {
                        query: Arc::new(SourceQuery {
                            medium: TransportMedium::Udp,
                            question: question.clone(),
                            transaction: 1,
                            addr: SocketAddr::new(nsaddr, 43),
                        }),
                        ra: true,
                        aa: false,
                        result: TransactionResult::Failure(Error::new(ResponseCode::NxDomain, "")),
                    }),
                );

                assert_eq!(
                    server.anwsers(),
                    [FinishedTransaction {
                        query: Arc::new(SourceQuery {
                            medium: TransportMedium::Udp,
                            question: question.clone(),
                            transaction: 1,
                            addr,
                        }),
                        ra: true,
                        aa: false,
                        result: TransactionResult::Failure(Error::new(ResponseCode::NxDomain, "")),
                    }]
                );
                assert_eq!(server.ns_queries(), []);

                Ok(())
            }),
        );
        let _ = Builder::seeded(123).max_time(100.0.into()).build(sim).run();
    }

    #[test]
    #[serial]
    fn timeout_will_end_in_error() {
        let mut sim = Sim::new(()).with_stack(inet::init);
        sim.node(
            "alice",
            AsyncFn::io(|_| async move {
                let zone = Zonefile::from_str(ZONEFILE_ORG)?;
                let mut server = RecursiveNameserver::new(zone)?;

                let addr = "2.2.2.2:2".parse().unwrap();
                server.incoming(
                    TransportMedium::Udp,
                    addr,
                    DnsMessage::question_a(1, "alice.example.org.".parse::<DnsString>()?),
                );

                assert_eq!(server.anwsers().len(), 0);
                assert_eq!(server.ns_queries().len(), 1);

                sleep(Duration::from_secs(2)).await;

                server.tick();
                assert_eq!(
                    server.anwsers(),
                    [FinishedTransaction {
                        query: Arc::new(SourceQuery {
                            medium: TransportMedium::Udp,
                            question: Question {
                                qname: "alice.example.org.".parse()?,
                                qclass: QuestionClass::IN,
                                qtyp: QuestionTyp::A
                            },
                            transaction: 1,
                            addr,
                        }),
                        ra: true,
                        aa: false,
                        result: TransactionResult::Failure(Error::new(ResponseCode::NxDomain, ""))
                    }]
                );

                Ok(())
            }),
        );
        let _ = Builder::seeded(123).max_time(100.0.into()).build(sim).run();
    }

    const ZONEFILE_EXAMPLE_ORG: &str = include_str!("../examples/example.org.zone");

    #[test]
    #[serial]
    fn timeout_will_retransmit_to_other_ns() {
        let mut sim = Sim::new(()).with_stack(inet::init);
        sim.node(
            "alice",
            AsyncFn::io(|_| async move {
                let zone = Zonefile::from_str(ZONEFILE_EXAMPLE_ORG)?;
                let mut server = RecursiveNameserver::new(zone)?;

                let addr = "2.2.2.2:2".parse().unwrap();
                server.incoming(
                    TransportMedium::Udp,
                    addr,
                    DnsMessage::question_a(1, "www.subdomain.example.org.".parse::<DnsString>()?),
                );

                assert_eq!(server.anwsers().len(), 0);
                assert_eq!(server.ns_queries().len(), 1);

                sleep(Duration::from_secs(2)).await;
                server.tick();

                assert_eq!(server.anwsers().len(), 0);
                assert_eq!(server.ns_queries().len(), 1);

                sleep(Duration::from_secs(2)).await;
                server.tick();

                assert_eq!(server.anwsers().len(), 1);
                assert_eq!(server.ns_queries().len(), 0);

                Ok(())
            }),
        );
        let _ = Builder::seeded(123).max_time(100.0.into()).build(sim).run();
    }
}
