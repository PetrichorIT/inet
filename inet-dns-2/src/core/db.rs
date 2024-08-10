use std::{cell::Cell, collections::HashMap};

use crate::core::QuestionTyp;

use super::{
    record::{DnsResourceRecord, ResourceRecordTyp, SoaResourceRecord},
    DnsQuestion, DnsString, ResourceRecordClass,
};

#[derive(Debug)]
pub struct RecordMap {
    class: ResourceRecordClass,
    entries: Vec<Entry>,
    cached_hit: Cell<usize>,
}

#[derive(Debug, PartialEq, Eq)]
struct Entry {
    name: DnsString,
    records: Vec<DnsResourceRecord>,
}

impl Entry {
    fn new(kv_pair: (DnsString, Vec<DnsResourceRecord>)) -> Self {
        let mut records = kv_pair.1;
        records.sort_by_key(|r| r.typ().to_raw_repr());
        Self {
            name: kv_pair.0,
            records,
        }
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
}

impl FromIterator<DnsResourceRecord> for RecordMap {
    fn from_iter<T: IntoIterator<Item = DnsResourceRecord>>(iter: T) -> Self {
        let iter = iter.into_iter();
        let mut map = HashMap::new();
        for value in iter {
            let entry = map.entry(value.name().clone()).or_insert(Vec::new());
            entry.push(value);
        }

        let mut entries = map.into_iter().map(Entry::new).collect::<Vec<_>>();
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
    use std::{io, str::FromStr};

    use crate::core::{ResourceRecordTyp, Zonefile};

    use super::*;

    const RAW_A: &str = r#"
$ORIGIN example.com.     ; designates the start of this zone file in the namespace
$TTL 3600                ; default expiration time (in seconds) of all RRs without their own TTL value
example.com.  IN  SOA   ns.example.com. username.example.com. ( 2020091025 7200 3600 1209600 3600 )
example.com.  IN  NS    ns                    ; ns.example.com is a nameserver for example.com
example.com.  IN  NS    ns.somewhere.example. ; ns.somewhere.example is a backup nameserver for example.com
example.com.  IN  MX    10 mail.example.com.  ; mail.example.com is the mailserver for example.com
@             IN  MX    20 mail2.example.com. ; equivalent to above line, "@" represents zone origin
@             IN  MX    50 mail3              ; equivalent to above line, but using a relative host name
example.com.  IN  A     192.0.2.1             ; IPv4 address for example.com
              IN  AAAA  2001:db8:10::1        ; IPv6 address for example.com
ns            IN  A     192.0.2.2             ; IPv4 address for ns.example.com
              IN  AAAA  2001:db8:10::2        ; IPv6 address for ns.example.com
www           IN  CNAME example.com.          ; www.example.com is an alias for example.com
wwwtest       IN  CNAME www                   ; wwwtest.example.com is another alias for www.example.com
mail          IN  A     192.0.2.3             ; IPv4 address for mail.example.com
mail2         IN  A     192.0.2.4             ; IPv4 address for mail2.example.com
mail3         IN  A     192.0.2.5             ; IPv4 address for mail3.example.com
    "#;

    #[test]
    fn multi_entry_query() -> io::Result<()> {
        let zf = Zonefile::from_str(RAW_A)?;
        let map = zf
            .records
            .into_iter()
            .flat_map(|r| DnsResourceRecord::try_from(r))
            .collect::<RecordMap>();

        let result = map.get(&DnsString::new("example.com."), ResourceRecordTyp::NS);
        dbg!(result);
        assert_eq!(result.len(), 2);

        Ok(())
    }
}
