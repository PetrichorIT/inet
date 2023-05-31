#![allow(unused)]

use des::time::SimTime;
use inet_types::dns::DNSResourceRecord;
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DnsDb {
    records: Vec<DNSResourceRecord>,
    cache: Vec<(DNSResourceRecord, SimTime)>,
    next_deadline: SimTime,
}

impl DnsDb {
    pub fn new() -> Self {
        Self {
            records: Vec::new(),
            cache: Vec::new(),
            next_deadline: SimTime::MAX,
        }
    }

    pub fn from_zonefile(records: Vec<DNSResourceRecord>) -> Self {
        Self {
            records,
            cache: Vec::new(),
            next_deadline: SimTime::MAX,
        }
    }

    pub fn cleanup(&mut self) {
        if SimTime::now() < self.next_deadline {
            return;
        }
        self.cache.retain(|e| e.1 > SimTime::now())
    }

    pub fn add(&mut self, record: DNSResourceRecord) {
        self.records.push(record)
    }

    pub fn add_cached(&mut self, record: DNSResourceRecord) {
        let deadline = SimTime::now() + Duration::from_secs(record.ttl as u64);
        self.next_deadline = self.next_deadline.min(deadline);
        self.cache.push((record, deadline))
    }

    pub fn find(
        &self,
        f: impl FnMut(&&DNSResourceRecord) -> bool,
    ) -> impl Iterator<Item = &DNSResourceRecord> {
        self.records
            .iter()
            .chain(self.cache.iter().map(|v| &v.0))
            .filter(f)
    }
}
