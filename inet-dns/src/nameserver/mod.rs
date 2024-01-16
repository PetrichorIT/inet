use super::DNSZoneFile;
use crate::{
    real_dns_resolver,
    types::{
        DNSClass, DNSMessage, DNSNodeInformation, DNSOpCode, DNSQuestion, DNSResourceRecord,
        DNSResponseCode, DNSSOAResourceRecord, DNSString, DNSType,
    },
};
use bytepack::{FromBytestream, ToBytestream};
use des::{
    prelude::{current, par},
    time::sleep,
    time::SimTime,
};
use inet::{dns::set_dns_resolver, UdpSocket};
use inet_types::ip::IpMask;
use std::{
    collections::VecDeque,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    str::FromStr,
    time::Duration,
};

mod iterative;
mod recursive;
mod root;

mod db;
use db::DnsDb;

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

    deadline: SimTime,
}

impl DNSNameserver {
    pub fn client(ip: IpAddr) -> Self {
        DNSNameserver::new(
            DNSNodeInformation {
                zone: DNSString::from(format!("{}", ip)),
                domain_name: DNSString::new(""),
                ip,
            },
            DNSSOAResourceRecord {
                name: DNSString::new(""),
                class: DNSClass::Internet,
                ttl: 7000,
                mname: DNSString::new(""),
                rname: DNSString::new(""),
                serial: 7000,
                refresh: 7000,
                retry: 7000,
                expire: 7000,
                minimum: 7000,
            },
        )
    }

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
            ip: IpAddr::from_str(&par("addr").as_option().expect(&format!(
                "failed to get par 'addr' for module {}",
                current().path()
            )))
            .unwrap(),
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
        set_dns_resolver(real_dns_resolver)?;

        let socket =
            UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 53)).await?;

        tracing::trace!("Created socket at {}", socket.local_addr().unwrap());

        let mut buf = [0u8; 512];
        loop {
            if self.active_transactions.is_empty() {
                let udp = socket.recv_from(&mut buf).await;
                let Ok((n, from)) = udp else { break };
                let Ok(msg) = DNSMessage::read_from_slice(&mut &buf[..n]) else {
                    continue;
                };

                let output = self.handle(msg, from);
                for (pkt, target) in output {
                    let buf = pkt.to_vec()?;
                    socket.send_to(&buf, target).await?;
                }
            } else {
                // Wait with timeout only if active transactions
                // else infinite loop, will not terminated unless sim end
                tokio::select! {
                    udp = socket.recv_from(&mut buf) => {
                        let Ok((n, from)) = udp else { break };
                        let Ok(msg) = DNSMessage::read_from_slice(&mut &buf[..n]) else { continue };

                        let output = self.handle(msg, from);
                        for (pkt, target) in output {
                            let buf = pkt.to_vec()?;
                            socket.send_to(&buf, target).await?;
                        }
                    },
                    _ = sleep(Duration::new(5, 0)) => {
                        let mut output = Vec::new();
                        self.check_timeouts(&mut output);
                        for (pkt, target) in output {
                            let buf = pkt.to_vec()?;
                            socket.send_to(&buf, target).await?;
                        }
                    }
                }
            }
        }

        tracing::trace!("Closed socket at {}", socket.local_addr().unwrap());

        Ok(())
    }

    pub fn handle(&mut self, msg: DNSMessage, source: SocketAddr) -> Vec<(DNSMessage, SocketAddr)> {
        let mut output = Vec::new();
        if msg.qr {
            // REPLY
            self.handle_response(msg, source, &mut output);
        } else {
            // QUERY
            self.handle_request(msg, source, &mut output);
        }
        self.check_timeouts(&mut output);
        output
    }

    fn check_timeouts(&mut self, output: &mut Vec<(DNSMessage, SocketAddr)>) {
        let mut i = 0;
        while i < self.active_transactions.len() {
            if self.active_transactions[i].deadline < SimTime::now() {
                let transaction = self.active_transactions.remove(i);
                tracing::trace!(
                    "[0x{:x}] Recursive transaction 0x{:x} timed out",
                    transaction.client_transaction,
                    transaction.local_transaction
                );

                // anwser with timeout
                let mut response = self.response_for_request(&transaction.client_req, true);
                response.questions.push(transaction.client_question);
                response.rcode = DNSResponseCode::ServFail;
                output.push((response, transaction.client))
            } else {
                i += 1;
            }
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
        tracing::trace!(
            "[0x{:x}] Got request from {} with {} questions in mode {:?} (ra = {})",
            msg.transaction,
            client,
            msg.questions.len(),
            mode,
            ra
        );

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
