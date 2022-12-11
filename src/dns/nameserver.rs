use tokio::net::UdpSocket;

use super::{
    DNSClass, DNSMessage, DNSOpCode, DNSQuestion, DNSResourceRecord, DNSResponseCode, DNSString,
    DNSType, DNSZoneFile,
};
use crate::{FromBytestream, IntoBytestream};
use std::{
    collections::VecDeque,
    net::{IpAddr, Ipv4Addr, SocketAddr},
};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DNSNameserver {
    zone: DNSString,
    soa: DNSSOAResourceRecord,
    records: Vec<DNSResourceRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DNSSOAResourceRecord {
    pub name: DNSString,
    // type,
    pub class: DNSClass,
    pub ttl: i32,
    pub mname: DNSString,
    pub rname: DNSString,
    pub serial: i32,
    pub refresh: i32,
    pub retry: i32,
    pub expire: i32,
    pub minimum: i32,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DNSNSResourceRecord {
    pub name: DNSString,
    pub ttl: i32,
    pub class: DNSClass,
    pub ns: Vec<DNSResourceRecord>,
}

impl DNSNameserver {
    pub fn new(zone: impl Into<DNSString>, soa: DNSSOAResourceRecord) -> Self {
        Self {
            zone: zone.into(),
            soa,
            records: Vec::new(),
        }
    }

    pub fn from_zonefile(
        zone: impl Into<DNSString>,
        zone_filedir: impl AsRef<str>,
    ) -> std::io::Result<Self> {
        let DNSZoneFile { zone, soa, records } = DNSZoneFile::new(zone, zone_filedir)?;
        Ok(Self { zone, soa, records })
    }

    pub fn info(&self) {
        println!("{} soa {:?}", self.zone, self.soa);
        for record in &self.records {
            println!("{}", record);
        }
    }

    pub fn add_address_entry(
        &mut self,
        name: impl Into<DNSString>,
        addr: IpAddr,
        ttl: Option<i32>,
        class: Option<DNSClass>,
    ) {
        let name = name.into();
        let ttl = ttl.unwrap_or(self.soa.ttl);
        let class = class.unwrap_or(DNSClass::Internet);

        match addr {
            IpAddr::V4(v4) => {
                let entry = DNSResourceRecord {
                    name,
                    ttl,
                    class,
                    typ: DNSType::A,
                    rdata: Vec::from(v4.octets()),
                };
                self.records.push(entry);
            }
            IpAddr::V6(v6) => {
                let entry = DNSResourceRecord {
                    name,
                    ttl,
                    class,
                    typ: DNSType::AAAA,
                    rdata: Vec::from(v6.octets()),
                };
                self.records.push(entry);
            }
        }
    }

    pub fn add_cname_entry(
        &mut self,
        name: impl Into<DNSString>,
        cname: impl Into<DNSString>,
        ttl: Option<i32>,
        class: Option<DNSClass>,
    ) {
        let name = name.into();
        let cname: DNSString = cname.into();
        let ttl = ttl.unwrap_or(self.soa.ttl);
        let class = class.unwrap_or(DNSClass::Internet);

        let mut cname_bytes = Vec::new();
        cname
            .into_bytestream(&mut cname_bytes)
            .expect("Failed to encode DNSString");

        let entry = DNSResourceRecord {
            name,
            class,
            ttl,
            typ: DNSType::CNAME,
            rdata: cname_bytes,
        };
        self.records.push(entry);
    }

    pub fn add_ptr_entry(
        &mut self,
        ip: IpAddr,
        rname: impl Into<DNSString>,
        ttl: Option<i32>,
        class: Option<DNSClass>,
    ) {
        let req_name: DNSString = match ip {
            IpAddr::V4(v4) => {
                let v4 = v4.octets();
                format!("{}.{}.{}.{}.in-addr.arpa.", v4[3], v4[2], v4[1], v4[0]).into()
            }
            IpAddr::V6(v6) => {
                let v6 = v6.octets();
                let mut s = String::new();
                for byte in v6.iter().rev() {
                    s.push_str(&format!("{}.", byte))
                }
                s.push_str("ip6.arpa.");
                s.into()
            }
        };
        let rname: DNSString = rname.into();
        let ttl = ttl.unwrap_or(self.soa.ttl);
        let class = class.unwrap_or(DNSClass::Internet);

        let mut rname_bytes = Vec::new();
        rname
            .into_bytestream(&mut rname_bytes)
            .expect("Failed to encode DNSString");

        let entry = DNSResourceRecord {
            name: req_name,
            class,
            ttl,
            typ: DNSType::PTR,
            rdata: rname_bytes,
        };

        self.records.push(entry);
    }

    pub fn add_ns_entry(
        &mut self,
        name: impl Into<DNSString>,
        ns: impl Into<DNSString>,
        ttl: Option<i32>,
        class: Option<DNSClass>,
    ) {
        let name = name.into();
        let ns: DNSString = ns.into();
        let ttl = ttl.unwrap_or(self.soa.ttl);
        let class = class.unwrap_or(DNSClass::Internet);

        let ns_bytes = ns.into_buffer().expect("Failed to parse ns to DNSStirng");

        let entry = DNSResourceRecord {
            name,
            class,
            ttl,
            typ: DNSType::NS,
            rdata: ns_bytes,
        };

        self.records.push(entry);
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

            let Some(resp) = self.handle(msg) else { continue };
            let mut buf = Vec::with_capacity(512);
            resp.into_bytestream(&mut buf)?;
            socket.send_to(&buf, client).await?;
        }

        Ok(())
    }

    pub fn handle(&mut self, mut req: DNSMessage) -> Option<DNSMessage> {
        if req.qr != false {
            log::error!("Received response with opcode {:?}", req.opcode);
            return None;
        }

        // Since we do only iterativ DNS only questions must be considered
        let mut response = DNSMessage {
            transaction: req.transaction,
            qr: true,
            opcode: DNSOpCode::Query,
            aa: self.is_auth(),
            tc: false,
            rd: false,
            ra: false,
            rcode: DNSResponseCode::NoError,

            questions: Vec::new(),
            anwsers: Vec::new(),
            auths: Vec::new(),
            additional: Vec::new(),
        };

        let mut questions = Vec::new();
        std::mem::swap(&mut questions, &mut req.questions);

        for question in questions {
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
                        continue;
                    }

                    // Check for A entries
                    let mut a_res = self
                        .records
                        .iter()
                        .filter(|record| {
                            record.class == qclass
                                && record.typ == DNSType::A
                                && record.name == qname
                        })
                        .collect::<VecDeque<_>>();

                    // Check whether we return a record or a referral
                    if a_res.is_empty() {
                        // println!("{} k = {} ")

                        let next_param = qname.suffix(qname.labels() - k - 1);
                        log::info!("Referral to next zone {} of {}", next_param, *qname);

                        let ns = self
                            .records
                            .iter()
                            .filter(|record| {
                                record.class == qclass
                                    && record.typ == DNSType::NS
                                    && record.name.suffix(0) == next_param
                            })
                            .cloned()
                            .collect::<Vec<_>>();

                        if ns.is_empty() {
                            log::error!("Cannot anweser question");
                            continue;
                        }

                        for nameserver in ns {
                            let nsbytes = nameserver.rdata.clone();
                            let uri = DNSString::from_buffer(nsbytes)
                                .expect("Failed to parse bytestring");
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
                        )
                    }

                    response.questions.push(DNSQuestion {
                        qname,
                        qtyp,
                        qclass,
                    });
                }
                // DNSType::AAAA => {
                //     let DNSQuestion {
                //         qclass,
                //         qname,
                //         qtyp,
                //     } = question;

                //     // Check whether this server is even relevant
                //     let zone_uri = &self.soa.name;
                //     let k = zone_uri.labels();

                //     if DNSString::suffix_match_len(&qname, &zone_uri) < k {
                //         log::warn!("ill directed request for {} in zone {}", qname, zone_uri);
                //         continue;
                //     }

                //     // Check for A entries
                //     let mut a_res = self
                //         .records
                //         .iter()
                //         .filter(|record| {
                //             record.class == qclass
                //                 && record.typ == DNSType::AAAA
                //                 && record.name == qname
                //         })
                //         .collect::<VecDeque<_>>();

                //     // Check whether we return a record or a referral
                //     if a_res.is_empty() {
                //         // println!("{} k = {} ")

                //         let next_param = qname.label(qname.labels() - k - 1);
                //         log::info!("Referral to next zone {} of {}", next_param, *qname);

                //         let ns = self
                //             .records
                //             .iter()
                //             .filter(|record| {
                //                 record.class == qclass
                //                     && record.typ == DNSType::NS
                //                     && record.name.trim_end_matches(|c| c == '.') == next_param
                //             })
                //             .cloned()
                //             .collect::<Vec<_>>();

                //         if ns.is_empty() {
                //             log::error!("Cannot anweser question");
                //             continue;
                //         }

                //         for nameserver in ns {
                //             let nsbytes = nameserver.rdata.clone();
                //             let uri = DNSString::from_buffer(nsbytes)
                //                 .expect("Failed to parse bytestring");
                //             self.add_node_information_to(
                //                 &[DNSType::A, DNSType::AAAA],
                //                 &uri,
                //                 &mut response.additional,
                //             );
                //             response.auths.push(nameserver);
                //         }
                //     } else {
                //         let anwser = a_res.pop_front().unwrap().clone();
                //         log::info!(
                //             "Responding with {} and {} additionaly records",
                //             anwser,
                //             a_res.len()
                //         );

                //         response.anwsers.push(anwser);
                //         for a in a_res {
                //             response.additional.push(a.clone())
                //         }

                //         self.add_node_information_to(
                //             &[DNSType::A],
                //             &qname,
                //             &mut response.additional,
                //         );
                //     }

                //     response.questions.push(DNSQuestion {
                //         qname,
                //         qtyp,
                //         qclass,
                //     });
                // }
                _ => unimplemented!(),
            }
        }

        Some(response)
    }

    fn add_node_information_to(
        &mut self,
        types: &[DNSType],
        node: &DNSString,
        response: &mut Vec<DNSResourceRecord>,
    ) {
        for typ in types {
            response.extend(
                self.records
                    .iter()
                    .filter(|record| record.typ == *typ && record.name == *node)
                    .cloned(),
            )
        }
    }
}
