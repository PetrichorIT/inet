use des::time::SimTime;

use super::{
    record::{DnsResourceRecord, ResourceRecordTyp, SoaResourceRecord},
    DnsQuestion, DnsString, ResourceRecordClass,
};
use crate::core::QuestionTyp;
use std::{cell::Cell, collections::HashMap, time::Duration};

#[derive(Debug, Clone, Default)]
pub struct RecordMap {
    class: ResourceRecordClass,
    entries: Vec<Entry>,
    // TODO: Add caching mechanic
    cached_hit: Cell<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Entry {
    name: DnsString,
    timeouts: Vec<Option<SimTime>>,
    records: Vec<DnsResourceRecord>,
}

impl Entry {
    fn new_non_timeout(kv_pair: (DnsString, Vec<DnsResourceRecord>)) -> Self {
        let mut records = kv_pair.1;
        records.sort_by_key(|r| r.typ().to_raw_repr());
        Self {
            name: kv_pair.0,
            timeouts: vec![None; records.len()],
            records,
        }
    }

    fn add(&mut self, record: DnsResourceRecord, timeout: SimTime) {
        match self
            .records
            .binary_search_by_key(&record.typ().to_raw_repr(), |r| r.typ().to_raw_repr())
        {
            Ok(i) | Err(i) => {
                self.records.insert(i, record);
                self.timeouts.insert(i, Some(timeout));
            }
        }
    }

    fn tick(&mut self, now: SimTime) -> Vec<DnsResourceRecord> {
        let mut i = 0;
        let mut removed = Vec::new();
        while i < self.records.len() {
            if let Some(timeout) = self.timeouts[i] {
                if timeout <= now {
                    self.timeouts.remove(i);
                    removed.push(self.records.remove(i));
                    continue;
                }
            }
            i += 1;
        }
        removed
    }
}

impl PartialOrd for Entry {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Entry {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.name.cmp(&other.name)
    }
}

impl RecordMap {
    pub fn soa(&self) -> Option<&SoaResourceRecord> {
        for entry in &self.entries {
            for record in &entry.records {
                if record.typ() == ResourceRecordTyp::SOA {
                    return record.as_any().downcast_ref::<SoaResourceRecord>();
                }
            }
        }
        None
    }

    pub fn query(&self, question: &DnsQuestion) -> &[DnsResourceRecord] {
        assert!(question.qclass.includes(self.class));

        match question.qtyp {
            QuestionTyp::ANY => self
                .entries
                .binary_search_by_key(&&question.qname, |r| &r.name)
                .map(|i| &self.entries[i].records[..])
                .unwrap_or(&[]),
            other => self.get(
                &question.qname,
                ResourceRecordTyp::try_from(other).expect("failed"),
            ),
        }
    }

    pub fn get(&self, name: &DnsString, typ: ResourceRecordTyp) -> &[DnsResourceRecord] {
        if let Ok(i) = self.entries.binary_search_by_key(&name, |r| &r.name) {
            self.cached_hit.set(i);
            let mut start = None;
            let mut end = None;

            for (k, r) in self.entries[i].records.iter().enumerate() {
                let is_match = typ == r.typ();
                if is_match {
                    if start.is_none() {
                        start = Some(k);
                    }
                } else if start.is_some() && end.is_none() {
                    end = Some(k)
                }
            }
            if let Some(start) = start {
                if let Some(end) = end {
                    &self.entries[i].records[start..end]
                } else {
                    &self.entries[i].records[start..]
                }
            } else {
                &[]
            }
        } else {
            &[]
        }
    }

    pub fn add(&mut self, record: DnsResourceRecord, now: SimTime) {
        // FIXME: use default parameters
        let timeout = now + Duration::from_secs(record.ttl().unwrap_or(4242) as u64);
        match self
            .entries
            .binary_search_by_key(&record.name(), |r| &r.name)
        {
            Ok(i) => self.entries[i].add(record, timeout),
            Err(i) => {
                let mut entry = Entry::new_non_timeout((record.name().clone(), Vec::new()));
                entry.add(record, timeout);
                self.entries.insert(i, entry);
            }
        }
    }

    pub fn tick(&mut self, now: SimTime) -> Vec<DnsResourceRecord> {
        self.entries
            .iter_mut()
            .map(|entry| entry.tick(now))
            .reduce(|mut a, mut b| {
                a.append(&mut b);
                a
            })
            .unwrap_or(Vec::new())
    }
}

impl FromIterator<DnsResourceRecord> for RecordMap {
    fn from_iter<T: IntoIterator<Item = DnsResourceRecord>>(iter: T) -> Self {
        let iter = iter.into_iter();
        let mut map = HashMap::new();
        for value in iter {
            let entry = map.entry(value.name().clone()).or_insert(Vec::new());
            entry.push(value);
        }

        let mut entries = map
            .into_iter()
            .map(Entry::new_non_timeout)
            .collect::<Vec<_>>();
        entries.sort();

        Self {
            class: ResourceRecordClass::IN, // TODO
            entries,
            cached_hit: Cell::new(0),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{
        AAAAResourceRecord, AResourceRecord, CNameResourceRecord, NsResourceRecord, QuestionClass,
        ResourceRecordTyp, Zonefile,
    };
    use std::{
        io,
        net::{Ipv4Addr, Ipv6Addr},
        str::FromStr,
    };

    fn db_example_org() -> io::Result<RecordMap> {
        const RAW: &str = r#"
$ORIGIN example.com.
$TTL 3600
example.com.  IN  SOA   ns.example.com. username.example.com. ( 2020091025 7200 3600 1209600 3600 )
example.com.  IN  NS    ns
example.com.  IN  NS    ns.somewhere.example.org.
example.com.  IN  MX    10 mail.example.com.
@             IN  MX    20 mail2.example.com.
@             IN  MX    50 mail3
example.com.  IN  A     192.0.2.1
              IN  AAAA  2001:db8:10::1
ns            IN  A     192.0.2.2
              IN  AAAA  2001:db8:10::2
www           IN  CNAME example.com.
wwwtest       IN  CNAME www
mail          IN  A     192.0.2.3
mail2         IN  A     192.0.2.4
mail3         IN  A     192.0.2.5
        "#;
        Ok(Zonefile::from_str(RAW)?
            .records
            .into_iter()
            .collect::<RecordMap>())
    }

    #[test]
    fn request_only_entries_of_typ() -> io::Result<()> {
        let db = db_example_org()?;
        assert_eq!(
            db.get(&DnsString::from_str("example.com.")?, ResourceRecordTyp::NS),
            [
                NsResourceRecord {
                    domain: DnsString::from_str("example.com.")?,
                    ttl: 3600,
                    class: ResourceRecordClass::IN,
                    nameserver: DnsString::from_str("ns.example.com.")?,
                }
                .into(),
                NsResourceRecord {
                    domain: DnsString::from_str("example.com.")?,
                    ttl: 3600,
                    class: ResourceRecordClass::IN,
                    nameserver: DnsString::from_str("ns.somewhere.example.org.")?,
                }
                .into(),
            ]
        );
        Ok(())
    }

    #[test]
    fn cname_entries() -> io::Result<()> {
        let db = db_example_org()?;
        assert_eq!(
            db.get(
                &DnsString::from_str("wwwtest.example.com.")?,
                ResourceRecordTyp::CNAME
            ),
            [CNameResourceRecord {
                name: DnsString::from_str("wwwtest.example.com.")?,
                ttl: 3600,
                class: ResourceRecordClass::IN,
                target: DnsString::from_str("www.example.com.")?,
            }
            .into()]
        );
        Ok(())
    }

    #[test]
    fn request_all_entries_of_domain() -> io::Result<()> {
        let db = db_example_org()?;

        assert_eq!(
            db.query(&DnsQuestion {
                qname: DnsString::from_str("ns.example.com.")?,
                qclass: QuestionClass::IN,
                qtyp: QuestionTyp::ANY
            }),
            [
                AResourceRecord {
                    name: DnsString::from_str("ns.example.com.")?,
                    ttl: 3600,
                    class: ResourceRecordClass::IN,
                    addr: Ipv4Addr::new(192, 0, 2, 2)
                }
                .into(),
                AAAAResourceRecord {
                    name: DnsString::from_str("ns.example.com.")?,
                    ttl: 3600,
                    class: ResourceRecordClass::IN,
                    addr: Ipv6Addr::new(0x2001, 0x0db8, 0x0010, 0, 0, 0, 0, 2)
                }
                .into()
            ]
        );
        Ok(())
    }

    #[test]
    fn non_zonefile_entries_time_out() -> io::Result<()> {
        let mut map = RecordMap::default();
        map.add(
            AResourceRecord {
                name: DnsString::from_str("www.example.org.")?,
                ttl: 300,
                class: ResourceRecordClass::IN,
                addr: Ipv4Addr::new(8, 8, 8, 8),
            }
            .into(),
            0.0.into(),
        );

        assert_eq!(
            map.get(
                &DnsString::from_str("www.example.org.")?,
                ResourceRecordTyp::A
            )
            .len(),
            1
        );

        map.tick(200.0.into());
        assert_eq!(
            map.get(
                &DnsString::from_str("www.example.org.")?,
                ResourceRecordTyp::A
            )
            .len(),
            1
        );

        map.tick(400.0.into());
        assert_eq!(
            map.get(
                &DnsString::from_str("www.example.org.")?,
                ResourceRecordTyp::A
            )
            .len(),
            0
        );

        Ok(())
    }
}
