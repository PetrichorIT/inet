use std::{
    io,
    net::{IpAddr, SocketAddr},
};

use des::{runtime::random, time::SimTime};

use crate::core::{
    AAAAResourceRecord, AResourceRecord, DnsQuestion, DnsResponseCode, DnsString, DnsZoneResolver,
    NsResourceRecord, QuestionClass, QuestionTyp, ResourceRecordTyp, Zonefile,
};

use super::{
    iterative::DnsIterativeNameserver,
    transaction::{DnsFinishedTransaction, DnsTransaction},
    types::DnsNameserverQuery,
    DnsMessage, DnsNameserver,
};

pub struct DnsRecursiveNameserver {
    pub inner: DnsIterativeNameserver,

    pub queries: Vec<DnsNameserverQuery>,
    pub roots: Vec<IpAddr>,

    pub active_transactions: Vec<DnsTransaction>,
    pub finished_transactions: Vec<DnsFinishedTransaction>,
    pub transaction_num: u16,
}

impl DnsRecursiveNameserver {
    pub fn new(zone: Zonefile) -> io::Result<Self> {
        Ok(Self {
            inner: DnsIterativeNameserver::new(vec![DnsZoneResolver::new(zone)?]).with_cache(),

            queries: Vec::new(),
            roots: Vec::new(),

            active_transactions: Vec::new(),
            finished_transactions: Vec::new(),
            transaction_num: 1,
        })
    }

    pub fn with_roots(mut self, roots: Vec<IpAddr>) -> Self {
        self.roots = roots;
        self
    }

    pub fn handle(&mut self, client: SocketAddr, client_transaction: u16, question: DnsQuestion) {
        let tx = DnsTransaction {
            client,
            client_transaction,
            local_transaction: self.transaction_num,
            question,
            remote: None,
            deadline: SimTime::MAX,
            operation_counter: 0,
        };
        self.transaction_num += 1;
        self.query(tx);
    }

    pub fn get_addr_of(&self, domain: &DnsString) -> Option<IpAddr> {
        let response = self
            .inner
            .handle(&DnsQuestion {
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

    pub fn query(&mut self, mut tx: DnsTransaction) {
        println!("[{}] Computing {}", tx.id(), tx.question);
        tx.operation_counter += 1;
        match self.inner.handle(&tx.question) {
            Ok(response) => {
                // Direct anwser
                if !response.anwsers.is_empty() {
                    println!("[{}] Anwsered {}", tx.id(), tx.question);
                    self.finished_transactions.push(DnsFinishedTransaction {
                        client: tx.client,
                        question: tx.question,
                        response,
                    });
                    return;
                }

                // Referral to other NS
                if !response.auths.is_empty() {
                    let ns = response.auths[random::<usize>() % response.auths.len()]
                        .as_any()
                        .downcast_ref::<NsResourceRecord>()
                        .expect("Auths must be NS records")
                        .clone();

                    let ns_addr = self
                        .get_addr_of(&ns.nameserver)
                        .expect("no NS name resoultion");

                    println!(
                        "[{}] Delegating {} to {} ({})",
                        tx.id(),
                        tx.question,
                        ns.nameserver,
                        ns_addr
                    );

                    self.queries.push(DnsNameserverQuery {
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
                let root = self.roots[random::<usize>() % self.roots.len()];
                self.queries.push(DnsNameserverQuery {
                    transaction: tx.local_transaction,
                    nameserver_ip: root,
                    question: tx.question.clone(),
                });
                println!("[{}] Delegating {} to ROOT {} ", tx.id(), tx.question, root);

                self.active_transactions.push(tx);
            }
            Err(e) => {}
        }
    }

    pub fn include(&mut self, source: SocketAddr, msg: DnsMessage) {
        let Some(active_transaction_idx) = self
            .active_transactions
            .iter()
            .position(|t| t.local_transaction == msg.transaction)
        else {
            panic!("Unknown query");
        };

        let tx = self.active_transactions.remove(active_transaction_idx);

        if msg.rcode != DnsResponseCode::NoError {
            tracing::warn!(
                "[0x{:x}] Got response to transaction {} with errors {:?} from {}",
                tx.client_transaction,
                msg.transaction,
                msg.rcode,
                source
            );
            let mut resp = msg;
            resp.transaction = tx.client_transaction;
            // self.finished_transactions.push(DnsFinishedTransaction { client: tx.client, question: tx., response: () });
            return;
        }

        for record in msg.response() {
            self.inner.add_cached(record.clone());
        }

        //  Restate questions
        self.query(tx);
    }
}

impl DnsNameserver for DnsRecursiveNameserver {
    fn incoming(&mut self, source: SocketAddr, mut msg: DnsMessage) {
        self.handle(source, msg.transaction, msg.response.questions.remove(0));
    }
    fn queries(&mut self) -> impl Iterator<Item = DnsNameserverQuery> {
        self.queries.drain(..)
    }
    fn anwsers(&mut self) -> impl Iterator<Item = DnsFinishedTransaction> {
        self.finished_transactions.drain(..)
    }
}
