use inet_types::dns::{DNSMessage, DNSQuestion, DNSResponseCode, DNSString, DNSType};
use inet_types::FromBytestream;
use std::{collections::VecDeque, net::SocketAddr};

use super::DNSNameserver;

impl DNSNameserver {
    pub(super) fn anwser_question_iteratively(
        &mut self,
        req: &DNSMessage,
        question: DNSQuestion,
        client: SocketAddr,
        output: &mut Vec<(DNSMessage, SocketAddr)>,
    ) {
        let mut response = self.response_for_request(req, false);

        // Check whether this server is even relevant
        let zone_uri = &self.soa.name;
        let k = zone_uri.labels();

        if DNSString::suffix_match_len(&zone_uri, &question.qname) < k {
            tracing::warn!(
                target: "inet/dns",
                "[0x{:x}] Illdirected request for {} {} in zone {}",
                req.transaction,
                question.qtyp,
                question.qname,
                zone_uri
            );
            return;
        }

        match question.qtyp {
            DNSType::A => {
                let DNSQuestion {
                    qclass,
                    qname,
                    qtyp,
                } = question;

                // Check for A entries
                let mut addrs = self
                    .db
                    .find(|record| {
                        record.class == qclass && record.typ == DNSType::A && record.name == qname
                    })
                    .collect::<VecDeque<_>>();

                // Check whether we return a record or a referral
                if addrs.is_empty() {
                    let next_param = qname.suffix(qname.labels() - k - 1);
                    tracing::trace!(
                        target: "inet/dns",
                        "[0x{:x}] Referral of request {} {} to next zone {}",
                        req.transaction,
                        qtyp,
                        *qname,
                        next_param,
                    );

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
                        tracing::error!(
                            target: "inet/dns",
                            "[0x{:x}] Cannot refer request {} {} to any further point",
                            req.transaction,
                            qtyp,
                            *qname
                        );
                        response.rcode = DNSResponseCode::NxDomain;
                        output.push((response, client));

                        dbg!(&self.db);
                        dbg!(qname);
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
                    let anwser = addrs.pop_front().unwrap().clone();
                    tracing::trace!(
                        target: "inet/dns",
                        "[0x{:x}] Responding to request {} {} with {} and {} additionaly records",
                        req.transaction,
                        qtyp,
                        *qname,
                        anwser,
                        addrs.len()
                    );

                    response.anwsers.push(anwser);
                    for a in addrs {
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
            DNSType::AAAA => {
                let DNSQuestion {
                    qclass,
                    qname,
                    qtyp,
                } = question;

                // Check for A entries
                let mut addrs = self
                    .db
                    .find(|record| {
                        record.class == qclass
                            && record.typ == DNSType::AAAA
                            && record.name == qname
                    })
                    .collect::<VecDeque<_>>();

                // Check whether we return a record or a referral
                if addrs.is_empty() {
                    let next_param = qname.suffix(qname.labels() - k - 1);
                    tracing::trace!(
                        target: "inet/dns",
                        "[0x{:x}] Referral of request {} {} to next zone {}",
                        req.transaction,
                        qtyp,
                        *qname,
                        next_param,
                    );

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
                        tracing::error!(
                            target: "inet/dns",
                            "[0x{:x}] Cannot refer request {} {} to any further point",
                            req.transaction,
                            qtyp,
                            *qname,
                        );
                        response.rcode = DNSResponseCode::NxDomain;
                        output.push((response, client));
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
                    let anwser = addrs.pop_front().unwrap().clone();
                    tracing::trace!(
                        target: "inet/dns",
                        "[0x{:x}] Responding to request {} {} with {} and {} additionaly records",
                        req.transaction,
                        qtyp,
                        *qname,
                        anwser,
                        addrs.len()
                    );

                    response.anwsers.push(anwser);
                    for a in addrs {
                        response.additional.push(a.clone())
                    }

                    self.add_node_information_to(&[DNSType::A], &qname, &mut response.additional);
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
}
