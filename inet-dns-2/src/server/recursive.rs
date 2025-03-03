use std::{
    io,
    net::{IpAddr, SocketAddr},
};

use des::{runtime::random, time::SimTime};
use tracing::info_span;

use crate::{
    core::{
        AAAAResourceRecord, AResourceRecord, DnsString, Error, NsResourceRecord, Question,
        QuestionClass, QuestionTyp, ResourceRecordTyp, ResponseCode, ZoneResolver, Zonefile,
    },
    server::transaction::TransactionResult,
};

use super::{
    iterative::IterativeNameserver,
    transaction::{ActiveTransaction, FinishedTransaction},
    types::NameserverQuery,
    DnsMessage, Nameserver,
};

pub struct RecursiveNameserver {
    pub inner: IterativeNameserver,

    pub queries: Vec<NameserverQuery>,
    pub roots: Vec<(IpAddr, String)>,

    pub active_transactions: Vec<ActiveTransaction>,
    pub finished_transactions: Vec<FinishedTransaction>,
    pub transaction_num: u16,
}

impl RecursiveNameserver {
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

    pub fn with_roots(mut self, roots: Vec<(IpAddr, String)>) -> Self {
        self.roots = roots;
        self
    }

    pub fn handle_query(
        &mut self,
        client: SocketAddr,
        client_transaction: u16,
        question: Question,
    ) {
        let tx = ActiveTransaction {
            client,
            client_transaction,
            local_transaction: self.transaction_num,
            question,
            remote: None,
            deadline: SimTime::MAX,
            operation_counter: 0,
        };
        self.transaction_num += 1;
        info_span!(
            "tx",
            req = tx.client_transaction,
            resolve = tx.local_transaction
        )
        .in_scope(|| self.query(tx));
    }

    pub fn get_addr_of(&self, domain: &DnsString) -> Option<IpAddr> {
        let response = self
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

    pub fn query(&mut self, mut tx: ActiveTransaction) {
        tracing::trace!("querying '{}'", tx.question);
        tx.operation_counter += 1;
        match self.inner.query(&tx.question) {
            Ok(resp) => {
                // Direct anwser
                if !resp.anwsers.is_empty() {
                    tracing::trace!(
                        "anwsered query '{}' with {} anwsers: \n{}",
                        tx.question,
                        resp.anwsers.len(),
                        resp.anwsers[0]
                    );
                    self.finished_transactions.push(FinishedTransaction {
                        transaction: tx.client_transaction,
                        client: tx.client,
                        question: tx.question,
                        result: TransactionResult::Success(resp),
                    });
                    return;
                }

                // Referral to other NS
                if !resp.auths.is_empty() {
                    let ns = resp.auths[random::<usize>() % resp.auths.len()]
                        .as_any()
                        .downcast_ref::<NsResourceRecord>()
                        .expect("Auths must be NS records")
                        .clone();

                    let ns_addr = self
                        .get_addr_of(&ns.nameserver)
                        .expect("no NS name resoultion");

                    tracing::trace!(
                        "delegating '{}' to {} ({})",
                        tx.question,
                        ns.nameserver,
                        ns_addr
                    );

                    self.queries.push(NameserverQuery {
                        transaction: tx.local_transaction,
                        nameserver_ip: ns_addr,
                        question: tx.question.clone(),
                    });

                    tx.remote = Some(ns);
                    self.active_transactions.push(tx);

                    return;
                }

                // no anweser, and now extra info
                // refer to root servers
                let root = &self.roots[random::<usize>() % self.roots.len()];
                self.queries.push(NameserverQuery {
                    transaction: tx.local_transaction,
                    nameserver_ip: root.0,
                    question: tx.question.clone(),
                });
                tracing::trace!(
                    "delegating '{}' to root nameserver {:?} ",
                    tx.question,
                    root
                );

                self.active_transactions.push(tx);
            }
            Err(e) if e.response_code() == ResponseCode::NxDomain => {
                let root = &self.roots[random::<usize>() % self.roots.len()];
                self.queries.push(NameserverQuery {
                    transaction: tx.local_transaction,
                    nameserver_ip: root.0,
                    question: tx.question.clone(),
                });
                tracing::trace!(
                    "delegating '{}' to root nameserver {:?} ",
                    tx.question,
                    root
                );

                self.active_transactions.push(tx);
            }

            Err(e) => {
                tracing::error!("internal: {e}")
            }
        }
    }

    pub fn handle_response(&mut self, source: SocketAddr, msg: DnsMessage) {
        let Some(active_transaction_idx) = self
            .active_transactions
            .iter()
            .position(|t| t.local_transaction == msg.transaction)
        else {
            panic!("Unknown query");
        };

        let tx = self.active_transactions.remove(active_transaction_idx);

        info_span!(
            "tx",
            req = tx.client_transaction,
            resolve = tx.local_transaction
        )
        .in_scope(|| {
            if msg.rcode != ResponseCode::NoError {
                tracing::warn!("got response with errors {:?} from {}", msg.rcode, source);
                self.finished_transactions.push(FinishedTransaction {
                    client: tx.client,
                    question: tx.question,
                    transaction: tx.client_transaction,
                    result: TransactionResult::Failure(Error::new(msg.rcode, "")),
                });
                return;
            }

            tracing::trace!("got response: {} elements", msg.response().count());

            for record in msg.response() {
                self.inner.add_cached(record.clone());
            }

            //  Restate questions
            self.query(tx);
        });
    }
}

impl Nameserver for RecursiveNameserver {
    fn incoming(&mut self, source: SocketAddr, mut msg: DnsMessage) {
        if msg.qr {
            self.handle_response(source, msg);
        } else {
            self.handle_query(source, msg.transaction, msg.response.questions.remove(0));
        }
    }
    fn queries(&mut self) -> impl Iterator<Item = NameserverQuery> {
        self.queries.drain(..)
    }
    fn anwsers(&mut self) -> impl Iterator<Item = FinishedTransaction> {
        self.finished_transactions.drain(..)
    }
}

#[cfg(test)]
mod tests {
    use std::{net::Ipv4Addr, str::FromStr};

    use des::{
        net::{AsyncFn, Sim},
        runtime::Builder,
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
                    addr,
                    DnsMessage::question_a(1, "alice.example.org.".parse::<DnsString>()?),
                );

                let question = Question {
                    qname: "alice.example.org.".parse()?,
                    qclass: QuestionClass::IN,
                    qtyp: QuestionTyp::A,
                };
                let nsaddr = Ipv4Addr::new(192, 168, 2, 30).into();

                assert_eq!(server.anwsers().collect::<Vec<_>>(), []);
                assert_eq!(
                    server.queries().collect::<Vec<_>>(),
                    [NameserverQuery {
                        nameserver_ip: nsaddr,
                        transaction: 1,
                        question: question.clone()
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
                    SocketAddr::new(nsaddr, 43),
                    DnsMessage {
                        transaction: 1,
                        qr: true,
                        opcode: OpCode::Query,
                        aa: false,
                        tc: false,
                        rd: false,
                        ra: false,
                        rcode: ResponseCode::NoError,
                        response: resp.clone(),
                    },
                );

                assert_eq!(
                    server.anwsers().collect::<Vec<_>>(),
                    [FinishedTransaction {
                        transaction: 1,
                        client: addr,
                        question,
                        result: TransactionResult::Success(resp)
                    }]
                );
                assert_eq!(server.queries().collect::<Vec<_>>(), []);

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
                    addr,
                    DnsMessage::question_a(1, "alice.example.org.".parse::<DnsString>()?),
                );

                let question = Question {
                    qname: "alice.example.org.".parse()?,
                    qclass: QuestionClass::IN,
                    qtyp: QuestionTyp::A,
                };
                let nsaddr = Ipv4Addr::new(192, 168, 2, 30).into();

                assert_eq!(server.anwsers().collect::<Vec<_>>(), []);
                assert_eq!(
                    server.queries().collect::<Vec<_>>(),
                    [NameserverQuery {
                        nameserver_ip: nsaddr,
                        transaction: 1,
                        question: question.clone()
                    }]
                );

                server.incoming(
                    SocketAddr::new(nsaddr, 43),
                    DnsMessage::response_from_transaction(FinishedTransaction {
                        transaction: 1,
                        client: SocketAddr::new(nsaddr, 43),
                        question: question.clone(),
                        result: TransactionResult::Failure(Error::new(ResponseCode::NxDomain, "")),
                    }),
                );

                assert_eq!(
                    server.anwsers().collect::<Vec<_>>(),
                    [FinishedTransaction {
                        transaction: 1,
                        client: addr,
                        question: question.clone(),
                        result: TransactionResult::Failure(Error::new(ResponseCode::NxDomain, "")),
                    }]
                );
                assert_eq!(server.queries().collect::<Vec<_>>(), []);

                Ok(())
            }),
        );
        let _ = Builder::seeded(123).max_time(100.0.into()).build(sim).run();
    }
}
