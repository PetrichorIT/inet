#![allow(unused)]

use std::{
    collections::{BinaryHeap, HashMap},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    ops::Deref,
    sync::{atomic::AtomicU16, Arc},
    time::Duration,
};

use crate::{
    dns::{DNSMessage, DNSQuestion, DNSResponseCode},
    FromBytestream, IntoBytestream,
};

use super::{DNSClass, DNSResourceRecord, DNSString, DNSType};
use des::{runtime::random, time::SimTime};
use tokio::{net::UdpSocket, sync::Mutex};

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

#[derive(Clone, Debug)]
pub struct DNSResolver {
    root_ns: Arc<Vec<(String, IpAddr)>>,

    cache: Arc<Mutex<DNSCache>>,
    tranaction_num: Arc<AtomicU16>,
}

#[derive(Clone, Debug)]
struct DNSCache {
    entries: BinaryHeap<DNSCacheEntry>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct DNSCacheEntry {
    record: DNSResourceRecord,
    deadline: SimTime,
}

pub struct DNSResolveStateMachine {
    transaction_num: Arc<AtomicU16>,
    cache: Arc<Mutex<DNSCache>>,

    domain: DNSString,

    ns: DNSResourceRecord,
    nsip: IpAddr,

    active_req: Vec<(u16, IpAddr, DNSType)>,

    result: Vec<IpAddr>,
}

pub enum DNSStateMachineEvent {
    Initialize(),
    Response(DNSMessage, SocketAddr),
    Timeout(u16),
}

impl DNSResolver {
    pub fn new() -> Self {
        Self {
            root_ns: Arc::new(vec![(
                "A.ROOT-SERVERS.NET".to_string(),
                IpAddr::V4(Ipv4Addr::new(100, 100, 100, 100)),
            )]),

            cache: Arc::new(Mutex::new(DNSCache {
                entries: BinaryHeap::new(),
            })),
            tranaction_num: Arc::new(AtomicU16::new(0)), // random
        }
    }

    pub async fn _lookup_host(&self, domain_name: &str) -> DNSResolveStateMachine {
        let domain = DNSString::new(domain_name);
        let cache = self.cache.clone();
        let transaction_num = self.tranaction_num.clone();

        let mut ns = None;
        for i in 0..domain.labels() {
            let mut lock = cache.lock().await;
            let entries = lock.entries(domain.suffix(i));

            let addrs = entries
                .iter()
                .filter(|r| {
                    r.class == DNSClass::Internet && (r.typ == DNSType::A || r.typ == DNSType::AAAA)
                })
                .collect::<Vec<_>>();

            if i == 0 && addrs.len() > 0 {
                // Found cached entries
                // assumme cache is valid
                let result = addrs.into_iter().map(|r| addr_of_record!(r)).collect();
                drop(lock);

                return DNSResolveStateMachine {
                    ns: DNSResourceRecord {
                        name: DNSString::new(""),
                        typ: DNSType::NS,
                        class: DNSClass::Internet,
                        ttl: 0,
                        rdata: Vec::new(),
                    },
                    nsip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),

                    domain,
                    result,

                    active_req: Vec::new(),
                    transaction_num,
                    cache,
                };
            }

            // Fetch nameservers for subdomains
            let nameservers = entries
                .into_iter()
                .filter(|r| r.class == DNSClass::Internet && r.typ == DNSType::NS)
                .cloned()
                .collect::<Vec<_>>();

            if nameservers.len() > 0 {
                let mut nsip = Vec::new();
                for ns in nameservers {
                    if let Some(ip) = lock.get(domain_of_record!(ns).into_inner()).first() {
                        nsip.push((ns, *ip));
                    }
                }
                if nsip.is_empty() {
                    continue;
                }

                let choose_ns = nsip.remove(random::<usize>() % nsip.len());
                ns = Some(choose_ns);
                break;
            }
            // switch to next higher zone
        }

        // Resolve point
        let mut ns = ns.unwrap_or_else(|| {
            let v = self.root_ns[random::<usize>() % self.root_ns.len()].clone();
            (
                DNSResourceRecord {
                    name: DNSString::new("."),
                    class: DNSClass::Internet,
                    typ: DNSType::NS,
                    ttl: 17000,
                    rdata: DNSString::new(v.0).into_buffer().unwrap(),
                },
                v.1,
            )
        });

        DNSResolveStateMachine {
            transaction_num,
            cache,

            domain,
            ns: ns.0,
            nsip: ns.1,
            active_req: Vec::new(),

            result: Vec::new(),
        }
    }

    pub async fn lookup_host(&self, domain_name: &str) -> std::io::Result<Vec<IpAddr>> {
        let domain = DNSString::new(domain_name);
        let cache = self.cache.clone();
        let root_ns = self.root_ns.clone();
        let transaction_num = self.tranaction_num.clone();

        let task = tokio::spawn(async move {
            let socket = UdpSocket::bind("0.0.0.0:0").await?;
            let mut results = Vec::new();

            let mut ns = None;
            for i in 0..domain.labels() {
                let mut lock = cache.lock().await;
                let entries = lock.entries(domain.suffix(i));

                let addrs = entries
                    .iter()
                    .filter(|r| {
                        r.class == DNSClass::Internet
                            && (r.typ == DNSType::A || r.typ == DNSType::AAAA)
                    })
                    .collect::<Vec<_>>();

                if i == 0 && addrs.len() > 0 {
                    // Found cached entries
                    // assumme cache is valid
                    return Ok(addrs.into_iter().map(|r| addr_of_record!(r)).collect());
                }

                // Fetch nameservers for subdomains
                let nameservers = entries
                    .into_iter()
                    .filter(|r| r.class == DNSClass::Internet && r.typ == DNSType::NS)
                    .cloned()
                    .collect::<Vec<_>>();

                if nameservers.len() > 0 {
                    let mut nsip = Vec::new();
                    for ns in nameservers {
                        if let Some(ip) = lock.get(domain_of_record!(ns).into_inner()).first() {
                            nsip.push((ns, *ip));
                        }
                    }
                    if nsip.is_empty() {
                        continue;
                    }

                    let choose_ns = nsip.remove(random::<usize>() % nsip.len());
                    ns = Some(choose_ns);
                    break;
                }
                // switch to next higher zone
            }

            // Resolve point
            let mut ns = ns.unwrap_or_else(|| {
                let v = root_ns[random::<usize>() % root_ns.len()].clone();
                (
                    DNSResourceRecord {
                        name: DNSString::new("."),
                        class: DNSClass::Internet,
                        typ: DNSType::NS,
                        ttl: 17000,
                        rdata: DNSString::new(v.0).into_buffer().unwrap(),
                    },
                    v.1,
                )
            });

            log::trace!("Resolver starting at zone {} addr {}", ns.0.name, ns.1);
            loop {
                let req = DNSMessage::question_a(
                    transaction_num.fetch_add(1, std::sync::atomic::Ordering::SeqCst),
                    domain.clone(),
                );
                let buf = req.into_buffer().unwrap();
                let n = socket
                    .send_to(&buf, SocketAddr::new(ns.1, 53))
                    .await
                    .unwrap();

                assert_eq!(n, buf.len());

                let mut buf = vec![0; 512];
                let (n, addr) = socket.recv_from(&mut buf).await.unwrap();
                buf.truncate(n);

                assert_eq!(addr.ip(), ns.1);
                let response = DNSMessage::from_buffer(buf).unwrap();

                if response.rcode != DNSResponseCode::NoError {
                    panic!()
                }

                for r in response.response() {
                    log::trace!("> {}", r);
                }

                if response.anwsers.is_empty() {
                    // # Referral
                    assert!(!response.auths.is_empty());
                    let c_ns = &response.auths[random::<usize>() % response.auths.len()];
                    let c_ns_domain = domain_of_record!(c_ns);
                    let addr = response
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
                        "Refferall to new zone {} with nameserver {} at {}",
                        c_ns.name,
                        c_ns_domain,
                        addr
                    );
                    ns = (c_ns.clone(), addr);
                } else {
                    // # Anwser
                    let mut results = Vec::new();
                    for anwser in response.anwsers {
                        if anwser.typ == DNSType::A || anwser.typ == DNSType::AAAA {
                            results.push(addr_of_record!(anwser))
                        }
                    }

                    for anwser in response.additional {
                        if anwser.name == domain
                            && (anwser.typ == DNSType::A || anwser.typ == DNSType::AAAA)
                        {
                            results.push(addr_of_record!(anwser))
                        }
                    }

                    return Ok(results);
                }
            }

            // loop {
            // }
            Ok(results)
        });
        task.await.unwrap()
    }
}

impl DNSResolveStateMachine {
    pub async fn solve_with_socket(&mut self) -> std::io::Result<Vec<IpAddr>> {
        let socket = UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)).await?;

        let pkts = self.handle(DNSStateMachineEvent::Initialize()).await;
        for (pkt, target) in pkts {
            let buf = pkt.into_buffer()?;
            let n = socket.send_to(&buf, SocketAddr::new(target, 53)).await?;

            if n != buf.len() {
                log::error!("Could not send packet of length {} bytes", buf.len());
            }
        }

        loop {
            match self.result() {
                Some(result) => return Ok(result.to_owned()),
                None => {}
            };

            let mut buf = vec![0; 512];
            let (n, nameserver) = socket.recv_from(&mut buf).await?;
            buf.truncate(n);

            let msg = DNSMessage::from_buffer(buf)?;
            let reqs = self
                .handle(DNSStateMachineEvent::Response(msg, nameserver))
                .await;

            for (pkt, target) in reqs {
                let buf = pkt.into_buffer()?;
                let n = socket.send_to(&buf, SocketAddr::new(target, 53)).await?;

                if n != buf.len() {
                    log::error!("Could not send packet of length {} bytes", buf.len());
                }
            }
        }
    }

    async fn handle(&mut self, event: DNSStateMachineEvent) -> Vec<(DNSMessage, IpAddr)> {
        let mut requests = Vec::new();
        match event {
            DNSStateMachineEvent::Initialize() => {
                if !self.result.is_empty() {
                    return Vec::new();
                }

                assert!(self.active_req.is_empty());
                let req = DNSMessage::question_a(
                    self.transaction_num
                        .fetch_add(1, std::sync::atomic::Ordering::SeqCst),
                    self.domain.clone(),
                );
                self.active_req
                    .push((req.transaction, self.nsip, DNSType::A));
                requests.push((req, self.nsip));

                log::trace!(
                    "Starting iterative resolve for {} at zone {} with nameserver {} ({})",
                    self.domain,
                    self.ns.name,
                    domain_of_record!(&self.ns),
                    self.nsip
                );
            }
            DNSStateMachineEvent::Response(response, nameserver) => {
                let req =
                    self.active_req.iter().enumerate().find(|(_, (id, ip, _))| {
                        response.transaction == *id && *ip == nameserver.ip()
                    });

                let Some((i, _)) = req else {
                    log::error!("Resolver got unexpected response {:x} from {}", response.transaction, nameserver);
                    return Vec::new();
                };
                let req = self.active_req.remove(i);

                if response.rcode != DNSResponseCode::NoError {
                    log::error!(
                        "Server anwesered with erronous respone code {:?}",
                        response.rcode
                    );
                    return Vec::new();
                }

                #[cfg(debug_assertions)]
                for r in response.response() {
                    log::trace!("> {}", r);
                }

                // Add elements to cache

                if response.anwsers.is_empty() {
                    // Auth referral or empty response
                    assert!(!response.auths.is_empty());
                    let c_ns = &response.auths[random::<usize>() % response.auths.len()];
                    let c_ns_domain = domain_of_record!(c_ns);
                    let addr = response
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
                    self.ns = c_ns.clone();
                    self.nsip = addr;

                    let req = DNSMessage::question_a(
                        self.transaction_num
                            .fetch_add(1, std::sync::atomic::Ordering::SeqCst),
                        self.domain.clone(),
                    );
                    self.active_req
                        .push((req.transaction, self.nsip, DNSType::A));
                    requests.push((req, self.nsip));
                } else {
                    // Resolve ended

                    for anwser in &response.anwsers {
                        if anwser.typ == DNSType::A || anwser.typ == DNSType::AAAA {
                            self.result.push(addr_of_record!(anwser))
                        }
                    }

                    for anwser in &response.additional {
                        if anwser.name == self.domain
                            && (anwser.typ == DNSType::A || anwser.typ == DNSType::AAAA)
                        {
                            self.result.push(addr_of_record!(anwser))
                        }
                    }
                }

                let mut cache = self.cache.lock().await;
                for record in response.into_records() {
                    cache.add(record.clone());
                }
                drop(cache);
            }
            DNSStateMachineEvent::Timeout(transaction) => {}
        };
        requests
    }

    fn result(&mut self) -> Option<&Vec<IpAddr>> {
        if self.result.is_empty() || !self.active_req.is_empty() {
            None
        } else {
            Some(&self.result)
        }
    }
}

impl DNSCache {
    fn add(&mut self, record: DNSResourceRecord) {
        let deadline = SimTime::now() + Duration::from_secs(record.ttl as u64);
        self.entries.push(DNSCacheEntry { record, deadline })
    }

    fn entries(&mut self, domain_name: impl AsRef<str>) -> Vec<&DNSResourceRecord> {
        let domain_name = domain_name.as_ref();
        self.entries
            .iter()
            .filter(|record| *record.name == domain_name)
            .map(|v| &v.record)
            .collect()
    }

    fn get(&self, domain_name: impl AsRef<str>) -> Vec<IpAddr> {
        let domain_name = domain_name.as_ref();
        self.entries
            .iter()
            .filter_map(|record| {
                if *record.name != domain_name {
                    None
                } else {
                    Some(addr_of_record!(record))
                }
            })
            .collect::<Vec<_>>()
    }

    fn clean(&mut self) {
        while let Some(peek) = self.entries.peek() {
            if peek.deadline <= SimTime::now() {
                self.entries.pop();
            } else {
                break;
            }
        }
    }
}

impl PartialOrd for DNSCacheEntry {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for DNSCacheEntry {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.deadline.cmp(&other.deadline)
    }
}

impl Deref for DNSCacheEntry {
    type Target = DNSResourceRecord;
    fn deref(&self) -> &Self::Target {
        &self.record
    }
}
