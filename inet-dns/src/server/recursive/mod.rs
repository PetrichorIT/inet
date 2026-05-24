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
        AAAAResourceRecord, AResourceRecord, DnsString, Error, NsResourceRecord, QueryResponse,
        Question, QuestionClass, QuestionTyp, ResourceRecordClass, ResourceRecordTyp, ResponseCode,
        ZoneResolver, Zonefile,
    },
    server::transaction::TransactionResult,
};

use super::{
    DnsMessage, Nameserver, NameserverQuery, TransportMedium,
    iterative::IterativeNameserver,
    transaction::{ActiveTransaction, FinishedTransaction, SourceQuery},
};

mod cfg;
pub use cfg::*;

#[cfg(test)]
mod tests;

/// A recursive nameserver.
///
/// This nameserver is responsible for resolving DNS queries recursively, starting from the root
/// nameservers and following the chain of referrals until the final answer is obtained.
#[derive(Debug)]
pub struct RecursiveNameserver {
    pub inner: IterativeNameserver,
    pub cache: ZoneResolver,

    pub cfg: Config,

    pub active_transactions: Vec<ActiveTransaction>,
    pub transaction_num: u16,

    // trait out
    pub queries: Vec<NameserverQuery>,
    pub finished_transactions: Vec<FinishedTransaction>,
}

impl RecursiveNameserver {
    /// Creates a new recursive nameserver.
    ///
    /// # Errors
    ///
    /// Fails if the zoneresolver fails.
    pub fn new(zone: Zonefile) -> io::Result<Self> {
        Ok(Self {
            inner: IterativeNameserver::primary(vec![ZoneResolver::new(zone)?]),
            cache: ZoneResolver::new(Zonefile::local())?,

            queries: Vec::new(),
            cfg: Config::default(),

            active_transactions: Vec::new(),
            finished_transactions: Vec::new(),
            transaction_num: 1,
        })
    }

    /// Adds a list of root nameservers to the recursive nameserver.
    #[must_use]
    pub fn with_roots(mut self, roots: Vec<(IpAddr, String)>) -> Self {
        self.cfg.roots = roots;
        self
    }

    fn query(&self, query: &Question) -> Result<(bool, QueryResponse), Error> {
        match self.inner.query(query) {
            // only delegate anwsers are possible
            Ok(response) if response.anwsers.is_empty() => {
                // try cache

                tracing::info!("cache entry");
                match self.cache.query(query) {
                    Ok(cache_response) if cache_response.anwsers.is_empty() => Ok((true, response)),
                    Ok(anwser) => Ok((false, anwser)),
                    Err(_) => Ok((true, response)),
                }
            }
            Ok(response) => Ok((true, response)),
            Err(err) if err.response_code() == ResponseCode::NxDomain => {
                if let Ok(response) = self.cache.query(query) {
                    // tracing::info!("cache entry: {response}");
                    Ok((false, response))
                } else {
                    Err(err)
                }
            }
            Err(err) => Err(err),
        }
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
            .query(&Question {
                qname: domain.clone(),
                qclass: QuestionClass::IN,
                qtyp: QuestionTyp::A,
            })
            .ok()?;

        if response.anwsers.is_empty() {
            None
        } else {
            let record = &response.anwsers[random::<u64>() as usize % response.anwsers.len()];
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
        tx.operation_counter += 1;
        match self.query(&tx.query.question) {
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
                        preferred: None,
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
                if self.cfg.roots.is_empty() {
                    tracing::error!("no root nameserver available");
                    self.finished_transactions.push(FinishedTransaction {
                        query: tx.query.clone(),
                        ra: true,
                        aa: true,
                        result: TransactionResult::Failure(Error::new(
                            ResponseCode::NxDomain,
                            format!("no root for query {}", tx.query.question),
                        )),
                    });
                    return;
                }

                let root = &self.cfg.roots[random::<u64>() as usize % self.cfg.roots.len()];
                self.queries.push(NameserverQuery {
                    transaction: tx.local_transaction,
                    nameserver_ip: root.0,
                    preferred: None,
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
                tracing::error!("internal: {e}");
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
                self.cache.add_cached(record.clone());
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
                    result: TransactionResult::Failure(Error::new(
                        ResponseCode::NxDomain,
                        format!(
                            "query '{}' could not be resolved: no more delegates",
                            tx.query
                        ),
                    )),
                });
            } else {
                let (ns, ns_addr) = &tx.remote[0];

                tracing::trace!("delegating to fallback {} ({})", ns.nameserver, ns_addr);

                self.queries.push(NameserverQuery {
                    transaction: tx.local_transaction,
                    nameserver_ip: *ns_addr,
                    preferred: None,
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
            let edns = msg.edns().cloned();
            for question in &msg.response.questions {
                let query = SourceQuery {
                    medium,
                    edns: edns.clone(),
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
                        match self.query(&query.question) {
                            Ok((authoratative, result)) => {
                                tracing::trace!("anwsered with:{}", result);
                                self.finished_transactions.push(FinishedTransaction {
                                    query,
                                    ra: false,
                                    aa: authoratative,
                                    result: TransactionResult::Success(result),
                                });
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
                        }
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
                preferred: None,
                query: tx.query.clone(),
            })
            .collect()
    }
}
