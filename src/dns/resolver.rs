#![allow(unused)]

use std::{
    collections::{BinaryHeap, HashMap},
    net::{IpAddr, Ipv4Addr},
    ops::Deref,
    time::Duration,
};

use super::{DNSResourceRecord, DNSType};
use des::{runtime::random, time::SimTime};
use tokio::net::UdpSocket;

#[derive(Clone, Debug)]
pub struct DNSResolver {
    root_ns: Vec<(String, IpAddr)>,

    cache: DNSCache,
    transactions: HashMap<u16, DNSTransaction>,
    tranaction_num: u16,
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

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum DNSTransaction {
    LookupV4(String),
    LookupV6(String),
}

impl DNSResolver {
    pub fn new() -> Self {
        Self {
            root_ns: vec![(
                "A.ROOT-SERVERS.NET".to_string(),
                IpAddr::V4(Ipv4Addr::new(100, 100, 100, 100)),
            )],

            cache: DNSCache {
                entries: BinaryHeap::new(),
            },
            transactions: HashMap::new(),
            tranaction_num: random(),
        }
    }

    pub async fn lookup_host(&mut self, domain_name: &str) -> std::io::Result<Vec<IpAddr>> {
        let task = tokio::spawn(async move {
            let socket = UdpSocket::bind("0.0.0.0:0").await?;

            Ok(Vec::new())
        });
        task.await.unwrap()
    }

    pub fn initiate_lookup_host(&mut self, host: &str) -> u16 {
        todo!()
    }
}

impl DNSCache {
    fn add(&mut self, record: DNSResourceRecord) {
        let deadline = SimTime::now() + Duration::from_secs(record.ttl as u64);
        self.entries.push(DNSCacheEntry { record, deadline })
    }

    fn get(&mut self, domain_name: impl AsRef<str>) -> Vec<IpAddr> {
        let domain_name = domain_name.as_ref();
        self.entries
            .iter()
            .filter_map(|record| {
                if *record.name != domain_name {
                    None
                } else {
                    match record.typ {
                        DNSType::A => {
                            let mut bytes = [0u8; 4];
                            for i in 0..4 {
                                bytes[i] = record.rdata[i]
                            }
                            Some(IpAddr::from(bytes))
                        }
                        DNSType::AAAA => {
                            let mut bytes = [0u8; 16];
                            for i in 0..16 {
                                bytes[i] = record.rdata[i]
                            }
                            Some(IpAddr::from(bytes))
                        }
                        _ => None,
                    }
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
