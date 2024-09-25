use std::net::SocketAddr;

use crate::core::{DnsError, DnsQuestion, DnsResourceRecord, DnsZoneResolver, QueryResponse};

use super::{
    transaction::DnsFinishedTransaction, types::DnsNameserverQuery, DnsMessage, DnsNameserver,
};

pub struct DnsIterativeNameserver {
    zones: Vec<DnsZoneResolver>,
    cache: Option<DnsZoneResolver>,

    respone: Option<DnsFinishedTransaction>,
}

impl DnsIterativeNameserver {
    pub fn new(mut zones: Vec<DnsZoneResolver>) -> Self {
        zones.sort_by_key(|resolver| resolver.zone().labels().len());
        Self {
            zones,
            cache: None,
            respone: None,
        }
    }

    pub fn with_cache(mut self) -> Self {
        self.cache = Some(DnsZoneResolver::cache());
        self
    }

    pub fn add_cached(&mut self, record: DnsResourceRecord) {
        if let Some(ref mut cache) = self.cache {
            cache.add_cached(record);
        }
    }

    pub fn handle(&self, question: &DnsQuestion) -> Result<QueryResponse, DnsError> {
        // DB tick
        let mut last_err = None;
        for zone in self
            .zones
            .iter()
            .chain(self.cache.iter())
            .filter(|z| z.accepts_query(question))
            .rev()
        {
            match zone.query(question) {
                Ok(anwser) => return Ok(anwser),
                Err(e) => last_err = Some(e),
            }
        }

        Err(last_err.take().unwrap())
    }
}

impl DnsNameserver for DnsIterativeNameserver {
    fn incoming(&mut self, source: SocketAddr, msg: DnsMessage) {
        self.respone = Some(DnsFinishedTransaction {
            response: self.handle(&msg.response.questions[0]).unwrap(),
            question: msg.response.questions[0].clone(),
            client: source,
        });
    }
    fn anwsers(&mut self) -> impl Iterator<Item = DnsFinishedTransaction> {
        self.respone.take().into_iter()
    }

    fn queries(&mut self) -> impl Iterator<Item = DnsNameserverQuery> {
        std::iter::empty()
    }
}
