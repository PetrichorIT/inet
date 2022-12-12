use self::db::DnsDb;

use super::{DNSMessage, DNSOpCode, DNSQuestion, DNSResponseCode, DNSString, DNSZoneFile};
use crate::{FromBytestream, IntoBytestream, IpMask};
use des::prelude::par;
use std::{
    collections::VecDeque,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    str::FromStr,
};
use tokio::net::UdpSocket;

mod db;

mod records;
pub use records::{DNSClass, DNSResourceRecord, DNSSOAResourceRecord, DNSType};

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

    db: DnsDb,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum DNSNameserverResolveMode {
    Iterative,
    Recursive,
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
            db: DnsDb::from_zonefile(records),
        })
    }
}

impl DNSNameserver {
    fn is_auth(&self) -> bool {
        true
    }

    pub async fn launch(&mut self) -> std::io::Result<()> {
        let socket =
            UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 53)).await?;

        log::trace!("Created socket at {}", socket.local_addr().unwrap());

        let mut buf = [0u8; 512];

        while let Ok((n, client)) = socket.recv_from(&mut buf).await {
            log::trace!("Got request from {} ({} bytes)", client, n);
            let vec = Vec::from(&buf[..n]);
            let Ok(msg) = DNSMessage::from_buffer(vec) else { continue };

            let Some(resp) = self.handle(msg, client) else { continue };
            let mut buf = Vec::with_capacity(512);
            resp.into_bytestream(&mut buf)?;
            socket.send_to(&buf, client).await?;
        }

        Ok(())
    }

    pub fn handle(&mut self, msg: DNSMessage, source: SocketAddr) -> Option<DNSMessage> {
        if msg.qr {
            // REPLY
            None
        } else {
            // QUERY
            Some(self.handle_request(msg, source))
        }
    }

    fn handle_request(&mut self, mut msg: DNSMessage, client: SocketAddr) -> DNSMessage {
        let (mode, ra) = self.get_mode(&msg, client);

        // Since we do only iterativ DNS only questions must be considered
        let mut response = DNSMessage {
            transaction: msg.transaction,
            qr: true,
            opcode: DNSOpCode::Query,
            aa: self.is_auth(),
            tc: false,
            rd: msg.rd,
            ra,
            rcode: DNSResponseCode::NoError,

            questions: Vec::new(),
            anwsers: Vec::new(),
            auths: Vec::new(),
            additional: Vec::new(),
        };

        let mut questions = Vec::new();
        std::mem::swap(&mut questions, &mut msg.questions);

        for question in questions {
            match mode {
                DNSNameserverResolveMode::Iterative => {
                    self.anwser_question_iteratively(question, &mut response)
                }
                DNSNameserverResolveMode::Recursive => unimplemented!(),
            }
        }

        response
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

    // fn anwser_question_recursivly(&mut self, question: DNSQuestion) {}

    fn anwser_question_iteratively(&mut self, question: DNSQuestion, response: &mut DNSMessage) {
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

                    self.add_node_information_to(&[DNSType::AAAA], &qname, &mut response.additional)
                }

                response.questions.push(DNSQuestion {
                    qname,
                    qtyp,
                    qclass,
                });
            }
            _ => unimplemented!(),
        }
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
