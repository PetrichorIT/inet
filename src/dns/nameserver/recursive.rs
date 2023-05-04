use crate::dns::{
    DNSClass, DNSMessage, DNSNameserver, DNSQuestion, DNSResourceRecord, DNSResponseCode,
    DNSString, DNSType,
};
use des::{runtime::random, time::SimTime};
use inet_types::{FromBytestream, IntoBytestream};
use std::{collections::VecDeque, net::SocketAddr, time::Duration};

use super::DNSTransaction;

const TIMEOUT: Duration = Duration::from_secs(5);

macro_rules! addr_of_record {
    ($r:ident) => {
        match $r.typ {
            crate::dns::DNSType::A => {
                let mut bytes = [0u8; 4];
                for i in 0..4 {
                    bytes[i] = $r.rdata[i]
                }
                ::std::net::IpAddr::from(bytes)
            }
            crate::dns::DNSType::AAAA => {
                let mut bytes = [0u8; 16];
                for i in 0..16 {
                    bytes[i] = $r.rdata[i]
                }
                ::std::net::IpAddr::from(bytes)
            }
            _ => unreachable!("Expected DNSResourceRecord with an address type."),
        }
    };
}

macro_rules! domain_of_record {
    ($r:expr) => {
        match $r.typ {
            crate::dns::DNSType::NS | crate::dns::DNSType::PTR => {
                <DNSString as FromBytestream>::from_buffer($r.rdata.clone())
                    .expect("Failed to parse rdata into DNSString")
            }
            _ => unreachable!("Expected DNSResourceRecord with domain name."),
        }
    };
}

impl DNSNameserver {
    pub(super) fn anwser_question_recursivly(
        &mut self,
        req: &DNSMessage,
        question: DNSQuestion,
        client: SocketAddr,
        output: &mut Vec<(DNSMessage, SocketAddr)>,
    ) {
        match question.qtyp {
            DNSType::A | DNSType::AAAA => {
                let DNSQuestion {
                    qname,
                    qclass,
                    qtyp,
                } = question;

                // (0) Find the best nameserver that we know
                let domain = qname.clone();
                let mut ns = None;
                for i in 0..domain.labels() {
                    // (1) Get all entries for the zone suffix (should be only NS, or A/AAAA if we are at i = 0)
                    let entries = self
                        .db
                        .find(|r| *r.name == domain.suffix(i))
                        .collect::<Vec<_>>();

                    // Happens only at i == 0
                    let addrs = entries
                        .iter()
                        .filter(|r| {
                            r.class == DNSClass::Internet
                                && (r.typ == DNSType::A || r.typ == DNSType::AAAA)
                        })
                        .collect::<Vec<_>>();

                    // (1) Direct resolve catch case
                    if i == 0 && addrs.len() > 0 {
                        log::trace!(
                            target: "inet/dns",
                            "[0x{:x}] Recursive query {} terminated due to {} cache entries",
                            req.transaction,
                            domain,
                            addrs.len()
                        );
                        // Found cached entries
                        // assumme cache is valid
                        let mut result = addrs
                            .into_iter()
                            // .map(|r| addr_of_record!(r))
                            .collect::<VecDeque<_>>();
                        let anwser = *result.pop_front().unwrap();
                        let mut response = self.response_for_request(req, true);

                        response.anwsers.push(anwser.clone());
                        for a in result {
                            response.additional.push((*a).clone())
                        }

                        output.push((response, client));
                        return;
                    }

                    // (2) Fetch NS entries check for NS resolve at i > 0
                    let nameservers = entries
                        .into_iter()
                        .filter(|r| r.class == DNSClass::Internet && r.typ == DNSType::NS)
                        .cloned()
                        .collect::<Vec<_>>();

                    // (3) If NS is available start resolve there
                    if nameservers.len() > 0 {
                        let mut nsip = Vec::new();
                        for ns in nameservers {
                            let domain = domain_of_record!(&ns);
                            let Some(ip) = self.db.find(|r| *r.name == *domain && (r.typ == DNSType::A || r.typ == DNSType::AAAA)).next() else {
                            continue;
                        };
                            nsip.push((ns, addr_of_record!(ip)))
                        }
                        if nsip.is_empty() {
                            continue;
                        }

                        let choose_ns = nsip.remove(random::<usize>() % nsip.len());
                        ns = Some(choose_ns);
                        break;
                    }
                    // (4) Switch to next higher zone
                }

                // (5) Mark resolve start point
                let (ns, nsip) = ns.unwrap_or_else(|| {
                    let v = self.one_root_ns();
                    (
                        DNSResourceRecord {
                            name: DNSString::new("."),
                            class: DNSClass::Internet,
                            typ: DNSType::NS,
                            ttl: 17000,
                            rdata: DNSString::new(v.1).into_buffer().unwrap(),
                        },
                        v.0,
                    )
                });

                let t = self.get_transaction_num();
                log::trace!(
                    target: "inet/dns",
                    "[0x{:x}] Initiaing recursion of {} {} with nameserver {} ({}) -> transaction {:x}",
                    req.transaction,
                    qtyp,
                    domain,
                    ns,
                    nsip,
                    t
                );

                let question = DNSQuestion {
                    qname: qname.clone(),
                    qtyp,
                    qclass,
                };
                let transaction = DNSTransaction {
                    client,
                    client_req: req.clone(),
                    client_question: question,
                    client_transaction: req.transaction,

                    local_transaction: t,
                    ns,
                    nsip,

                    deadline: SimTime::now() + TIMEOUT,
                };
                self.active_transactions.push(transaction);

                let mut request = DNSMessage::question_a(t, qname);
                request.rd = req.rd;
                request.questions[0].qtyp = qtyp;

                output.push((request, SocketAddr::new(nsip, 53)))
            }

            _ => unimplemented!(),
        }
    }

    pub(super) fn handle_response(
        &mut self,
        msg: DNSMessage,
        source: SocketAddr,
        output: &mut Vec<(DNSMessage, SocketAddr)>,
    ) {
        // (0) Resolver is in recursive mode
        // (1) Find corresponding transaction
        let Some((i, _)) = self.active_transactions.iter().enumerate().find(|(_, t)| t.local_transaction == msg.transaction) else {
            log::warn!(target: "inet/dns", "[0x{:x}] Got response to transaction not owned by this resolver from {}", msg.transaction, source);
            return;
        };
        let transaction = self.active_transactions.remove(i);
        assert_eq!(transaction.nsip, source.ip());

        if msg.rcode != DNSResponseCode::NoError {
            log::warn!(
                target: "inet/dns",
                "[0x{:x}] Got response to transaction {} with errors {:?} from {}",
                transaction.client_transaction,
                msg.transaction,
                msg.rcode,
                source
            );
            let mut resp = msg;
            resp.transaction = transaction.client_transaction;
            output.push((resp, transaction.client));
            return;
        }

        // Add entries to local cache
        for record in msg.response() {
            self.db.add_cached(record.clone());
        }

        if msg.anwsers.is_empty() {
            // (2.1) Got referalll must continue iterativly

            let c_ns = &msg.auths[random::<usize>() % msg.auths.len()];
            let c_ns_domain = domain_of_record!(c_ns);
            let addr = msg
                .additional
                .iter()
                .find(|r| {
                    r.class == c_ns.class
                        && (r.typ == DNSType::A || r.typ == DNSType::AAAA)
                        && r.name == c_ns_domain
                })
                .unwrap();

            let addr = addr_of_record!(addr);
            let t = self.get_transaction_num();
            log::trace!(
                target: "inet/dns",
                "[0x{:x}] Referal of request {} {} to next zone {} with nameserver {} at {} -> transaction {}",
                transaction.client_transaction,
                transaction.client_question.qtyp,
                transaction.client_question.qname,
                c_ns.name,
                c_ns_domain,
                addr,
                t
            );
            let domain = transaction.client_question.qname.clone();
            let new_transaction = DNSTransaction {
                local_transaction: t,
                ns: c_ns.clone(),
                nsip: addr,

                ..transaction
            };
            self.active_transactions.push(new_transaction);

            let req = DNSMessage::question_a(t, domain);
            output.push((req, SocketAddr::new(addr, 53)));
        } else {
            // (2.2) Upstream server provided anwsers
            log::trace!(
                target: "inet/dns",
                "[0x{:x}] Finished recursive resolve with anwser {} and {} additional records",
                transaction.client_transaction,
                msg.anwsers[0],
                msg.additional.len()
            );
            // Forward response to client
            let mut response = msg;
            response.transaction = transaction.client_transaction;
            output.push((response, transaction.client));
        }
    }
}
