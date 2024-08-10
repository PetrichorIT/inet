use super::DnsResourceRecord;

#[derive(Debug, Default, PartialEq, Eq)]
pub struct QueryResponse {
    pub anwsers: Vec<DnsResourceRecord>,
    pub auths: Vec<DnsResourceRecord>,
    pub additional: Vec<DnsResourceRecord>,
}

pub enum QueryResponseKind {
    Anwser,
    Auth,
    Additional,
}

impl QueryResponse {
    pub fn merge(&mut self, results: &[DnsResourceRecord], kind: QueryResponseKind) {
        let results = results.iter().cloned();
        match kind {
            QueryResponseKind::Anwser => self.anwsers.extend(results),
            QueryResponseKind::Auth => self.auths.extend(results),
            QueryResponseKind::Additional => self.additional.extend(results),
        }
    }

    pub fn anwser(anwsers: Vec<DnsResourceRecord>) -> Self {
        Self {
            anwsers,
            ..Default::default()
        }
    }

    pub fn referral(ns: Vec<DnsResourceRecord>, additional: Vec<DnsResourceRecord>) -> Self {
        Self {
            auths: ns,
            additional,
            ..Default::default()
        }
    }
}
