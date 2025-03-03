use std::fmt::Display;

use super::{DnsResourceRecord, Question};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct QueryResponse {
    pub questions: Vec<Question>,
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
    pub fn is_reponse_empty(&self) -> bool {
        self.anwsers.is_empty() && self.auths.is_empty()
    }

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

impl Display for QueryResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for answer in &self.anwsers {
            writeln!(f)?;
            write!(f, "> {}", answer)?;
        }
        for auth in &self.auths {
            writeln!(f)?;
            write!(f, "> {}", auth)?;
        }
        for additional in &self.additional {
            writeln!(f)?;
            write!(f, "+ {}", additional)?;
        }
        Ok(())
    }
}
