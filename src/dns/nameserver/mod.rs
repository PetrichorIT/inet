use self::db::DnsDb;

use super::{DNSMessage, DNSOpCode, DNSQuestion, DNSResponseCode, DNSString, DNSZoneFile};
use crate::{FromBytestream, IntoBytestream, IpMask};
use des::{prelude::par, runtime::random};
use std::{
    collections::VecDeque,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    str::FromStr,
};
use tokio::net::UdpSocket;

mod db;
mod records;
mod root;
pub use records::{DNSClass, DNSResourceRecord, DNSSOAResourceRecord, DNSType};

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
                <DNSString as crate::common::FromBytestream>::from_buffer($r.rdata.clone())
                    .expect("Failed to parse rdata into DNSString")
            }
            _ => unreachable!("Expected DNSResourceRecord with domain name."),
        }
    };
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DNSNodeInformation {
    pub zone: DNSString,
    pub domain_name: DNSString,
    pub ip: IpAddr,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DNSNameserver {
    node: DNSNodeInformation,
    soa: DNSSOAResourceRecord,
    mode_rules: VecDeque<(IpMask, Vec<DNSNameserverResolveMode>)>,

    active_transactions: Vec<DNSTransaction>,
    transaction_num: u16,

    db: DnsDb,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum DNSNameserverResolveMode {
    Iterative,
    Recursive,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct DNSTransaction {
    client: SocketAddr,
    client_req: DNSMessage,
    client_question: DNSQuestion,
    client_transaction: u16,

    local_transaction: u16,
    ns: DNSResourceRecord,
    nsip: IpAddr,
}

impl DNSNameserver {
    pub fn new(node: DNSNodeInformation, soa: DNSSOAResourceRecord) -> Self {
        Self {
            node,
            soa,
            mode_rules: VecDeque::from([
                (
                    IpMask::catch_all_v4(),
                    vec![DNSNameserverResolveMode::Iterative],
                ),
                (
                    IpMask::catch_all_v6(),
                    vec![DNSNameserverResolveMode::Iterative],
                ),
            ]),

            active_transactions: Vec::new(),
            transaction_num: 0,

            db: DnsDb::new(),
        }
    }

    pub fn from_zonefile(
        zone: impl Into<DNSString>,
        zone_filedir: impl AsRef<str>,
        domain_name: impl Into<DNSString>,
    ) -> std::io::Result<Self> {
        let DNSZoneFile { zone, soa, records } = DNSZoneFile::new(zone, zone_filedir)?;
        let node = DNSNodeInformation {
            zone,
            domain_name: domain_name.into(),
            ip: IpAddr::from_str(&par("addr").as_optional().unwrap()).unwrap(),
        };

        Ok(Self {
            node,
            soa,
            mode_rules: VecDeque::from([
                (
                    IpMask::catch_all_v4(),
                    vec![DNSNameserverResolveMode::Iterative],
                ),
                (
                    IpMask::catch_all_v6(),
                    vec![DNSNameserverResolveMode::Iterative],
                ),
            ]),

            active_transactions: Vec::new(),
            transaction_num: 0,

            db: DnsDb::from_zonefile(records),
        })
    }
}

impl DNSNameserver {
    fn is_auth(&self) -> bool {
        true
    }

    pub fn allow_recursive_for(&mut self, mask: IpMask) {
        self.mode_rules
            .push_front((mask, vec![DNSNameserverResolveMode::Recursive]))
    }
}

impl DNSNameserver {
    pub async fn launch(&mut self) -> std::io::Result<()> {
        let socket =
            UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 53)).await?;

        log::trace!("Created socket at {}", socket.local_addr().unwrap());

        let mut buf = [0u8; 512];

        while let Ok((n, client)) = socket.recv_from(&mut buf).await {
            log::trace!("Got message from {} ({} bytes)", client, n);
            let vec = Vec::from(&buf[..n]);
            let Ok(msg) = DNSMessage::from_buffer(vec) else { continue };

            let output = self.handle(msg, client);
            for (pkt, target) in output {
                let mut buf = Vec::with_capacity(512);
                pkt.into_bytestream(&mut buf)?;
                socket.send_to(&buf, target).await?;
            }
        }

        Ok(())
    }

    pub fn handle(&mut self, msg: DNSMessage, source: SocketAddr) -> Vec<(DNSMessage, SocketAddr)> {
        let mut output = Vec::new();
        if msg.qr {
            // REPLY
            log::trace!(
                "Got response to transaction {} from {}",
                msg.transaction,
                source
            );
            self.handle_response(msg, source, &mut output);
        } else {
            // QUERY
            log::trace!(
                "Got request for transaction {} from {}",
                msg.transaction,
                source
            );
            self.handle_request(msg, source, &mut output)
        }
        output
    }

    fn handle_response(
        &mut self,
        msg: DNSMessage,
        source: SocketAddr,
        output: &mut Vec<(DNSMessage, SocketAddr)>,
    ) {
        // (0) Resolver is in recursive mode
        // (1) Find corresponding transaction
        let Some((i, _)) = self.active_transactions.iter().enumerate().find(|(_, t)| t.local_transaction == msg.transaction) else {
            log::warn!("[R] Got response to transaction {} not owned by this resolver", msg.transaction);
            return;
        };
        let transaction = self.active_transactions.remove(i);
        assert_eq!(transaction.nsip, source.ip());

        if msg.rcode != DNSResponseCode::NoError {
            log::warn!(
                "[R] Got response with errors for transaction {}",
                msg.transaction
            );
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
            log::trace!(
                "Referall to new zone {} with nameserver {} at {}",
                c_ns.name,
                c_ns_domain,
                addr
            );

            let t = self.get_transaction_num();
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

            // Forward response to client
            let mut response = msg;
            response.transaction = transaction.client_transaction;
            output.push((response, transaction.client));
        }
    }

    fn handle_request(
        &mut self,
        mut msg: DNSMessage,
        client: SocketAddr,
        output: &mut Vec<(DNSMessage, SocketAddr)>,
    ) {
        self.db.cleanup();

        let (mode, ra) = self.get_mode(&msg, client);
        log::trace!("Request will be handled in mode {:?} (ra = {})", mode, ra);

        let mut questions = Vec::new();
        std::mem::swap(&mut questions, &mut msg.questions);

        for question in questions {
            match mode {
                DNSNameserverResolveMode::Iterative => {
                    self.anwser_question_iteratively(&msg, question, client, output)
                }
                DNSNameserverResolveMode::Recursive => {
                    self.anwser_question_recursivly(&msg, question, client, output)
                }
            }
        }
    }

    fn get_mode(&self, req: &DNSMessage, client: SocketAddr) -> (DNSNameserverResolveMode, bool) {
        let rule = self
            .mode_rules
            .iter()
            .find(|rule| rule.0.matches(client.ip()));

        if let Some((_, allowed_modes)) = rule {
            let recursion_requested = req.rd;
            let recursion_available = allowed_modes.contains(&DNSNameserverResolveMode::Recursive);
            if recursion_available && recursion_requested {
                (DNSNameserverResolveMode::Recursive, true)
            } else {
                (DNSNameserverResolveMode::Iterative, recursion_available)
            }
        } else {
            panic!("HUH")
        }
    }

    fn get_transaction_num(&mut self) -> u16 {
        self.transaction_num = self.transaction_num.wrapping_add(1);
        self.transaction_num
    }

    fn response_for_request(&self, req: &DNSMessage, ra: bool) -> DNSMessage {
        DNSMessage {
            transaction: req.transaction,
            qr: true,
            opcode: DNSOpCode::Query,
            aa: self.is_auth(),
            tc: false,
            rd: req.rd,
            ra,
            rcode: DNSResponseCode::NoError,

            questions: Vec::new(),
            anwsers: Vec::new(),
            auths: Vec::new(),
            additional: Vec::new(),
        }
    }

    fn anwser_question_recursivly(
        &mut self,
        req: &DNSMessage,
        question: DNSQuestion,
        client: SocketAddr,
        output: &mut Vec<(DNSMessage, SocketAddr)>,
    ) {
        match question.qtyp {
            DNSType::A => {
                let DNSQuestion {
                    qname,
                    qclass,
                    qtyp,
                } = question;

                // let zone_uri = &self.soa.name;
                // let k = zone_uri.labels();

                // TODO: If resolving recursivly ingore own identity
                // if DNSString::suffix_match_len(&zone_uri, &qname) < k {
                //     log::warn!("ill directed request for {} in zone {}", qname, zone_uri);
                //     return;
                // }

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
                            "Recursive query terminated due to {} cache entries",
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
                };
                self.active_transactions.push(transaction);

                let mut request = DNSMessage::question_a(t, qname);
                request.rd = true;

                output.push((request, SocketAddr::new(nsip, 53)))
            }
            _ => unimplemented!(),
        }
    }

    fn anwser_question_iteratively(
        &mut self,
        req: &DNSMessage,
        question: DNSQuestion,
        client: SocketAddr,
        output: &mut Vec<(DNSMessage, SocketAddr)>,
    ) {
        let mut response = self.response_for_request(req, false);

        match question.qtyp {
            DNSType::A => {
                let DNSQuestion {
                    qclass,
                    qname,
                    qtyp,
                } = question;

                // Check whether this server is even relevant
                let zone_uri = &self.soa.name;
                let k = zone_uri.labels();

                if DNSString::suffix_match_len(&zone_uri, &qname) < k {
                    log::warn!("ill directed request for {} in zone {}", qname, zone_uri);
                    return;
                }

                // Check for A entries
                let mut a_res = self
                    .db
                    .find(|record| {
                        record.class == qclass && record.typ == DNSType::A && record.name == qname
                    })
                    .collect::<VecDeque<_>>();

                // Check whether we return a record or a referral
                if a_res.is_empty() {
                    // println!("{} k = {} ")

                    let next_param = qname.suffix(qname.labels() - k - 1);
                    log::info!("Referral to next zone {} of {}", next_param, *qname);

                    let ns = self
                        .db
                        .find(|record| {
                            record.class == qclass
                                && record.typ == DNSType::NS
                                && record.name.suffix(0) == next_param
                        })
                        .cloned()
                        .collect::<Vec<_>>();

                    if ns.is_empty() {
                        log::error!("Cannot anweser question");
                        return;
                    }

                    for nameserver in ns {
                        let nsbytes = nameserver.rdata.clone();
                        let uri =
                            DNSString::from_buffer(nsbytes).expect("Failed to parse bytestring");
                        self.add_node_information_to(
                            &[DNSType::A, DNSType::AAAA],
                            &uri,
                            &mut response.additional,
                        );
                        response.auths.push(nameserver);
                    }
                } else {
                    let anwser = a_res.pop_front().unwrap().clone();
                    log::info!(
                        "Responding with {} and {} additionaly records",
                        anwser,
                        a_res.len()
                    );

                    response.anwsers.push(anwser);
                    for a in a_res {
                        response.additional.push(a.clone())
                    }

                    self.add_node_information_to(
                        &[DNSType::AAAA],
                        &qname,
                        &mut response.additional,
                    );
                }

                response.questions.push(DNSQuestion {
                    qname,
                    qtyp,
                    qclass,
                });
            }
            _ => unimplemented!(),
        }

        output.push((response, client))
    }

    fn add_node_information_to(
        &mut self,
        types: &[DNSType],
        node: &DNSString,
        response: &mut Vec<DNSResourceRecord>,
    ) {
        for typ in types {
            response.extend(
                self.db
                    .find(|record| record.typ == *typ && record.name == *node)
                    .cloned(),
            )
        }
    }
}
