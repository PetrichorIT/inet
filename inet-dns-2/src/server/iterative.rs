use std::net::SocketAddr;

use tracing::info_span;

use crate::core::{
    DnsError, DnsQuestion, DnsResourceRecord, DnsResponseCode, DnsZoneResolver, QueryResponse,
};

use super::{
    transaction::DnsFinishedTransaction, types::DnsNameserverQuery, DnsMessage, DnsNameserver,
};

pub struct DnsIterativeNameserver {
    zones: Vec<DnsZoneResolver>,
    cache: Option<DnsZoneResolver>,

    responses: Vec<DnsFinishedTransaction>,
}

impl DnsIterativeNameserver {
    pub fn new(mut zones: Vec<DnsZoneResolver>) -> Self {
        zones.sort_by_key(|resolver| resolver.zone().labels().len());
        Self {
            zones,
            cache: None,
            responses: Vec::new(),
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

    pub fn query(&self, question: &DnsQuestion) -> Result<QueryResponse, DnsError> {
        // TODO: db tick

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

        Err(last_err.take().unwrap_or_else(|| {
            DnsError::new(DnsResponseCode::NotZone, "request directed to invalid zone")
        }))
    }
}

impl DnsNameserver for DnsIterativeNameserver {
    fn incoming(&mut self, source: SocketAddr, msg: DnsMessage) {
        info_span!("tx", req = msg.transaction).in_scope(|| {
            for question in msg.response.questions {
                tracing::trace!("querying '{}'", question);
                match self.query(&question) {
                    Ok(result) => self.responses.push(DnsFinishedTransaction {
                        transaction: msg.transaction,
                        response: result,
                        question,
                        client: source,
                    }),
                    Err(e) => {
                        tracing::error!("query error: {e}");
                        return;
                    }
                };
            }
        });
    }

    fn anwsers(&mut self) -> impl Iterator<Item = DnsFinishedTransaction> {
        self.responses.drain(..).map(|v| {
            tracing::trace!("responding to '{}' with:{}", v.question, v.response);
            v
        })
    }

    fn queries(&mut self) -> impl Iterator<Item = DnsNameserverQuery> {
        std::iter::empty()
    }
}
