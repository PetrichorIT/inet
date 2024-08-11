use super::{DnsQuestion, DnsResourceRecord};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct QueryResponse {
    pub questions: Vec<DnsQuestion>,
    pub anwsers: Vec<DnsResourceRecord>,
    pub auths: Vec<DnsResourceRecord>,
    pub additional: Vec<DnsResourceRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QueryResponseKind {
    Anwser,
    Auth,
    Additional,
}

impl QueryResponse {
    pub fn merged(mut self, mut other: Self) -> Self {
        self.questions.append(&mut other.questions);
        self.anwsers.append(&mut other.anwsers);
        self.auths.append(&mut other.auths);
        self.additional.append(&mut other.additional);
        self
    }

    pub fn include(&mut self, results: &[DnsResourceRecord], kind: QueryResponseKind) {
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
