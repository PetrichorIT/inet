mod pkt;
mod root;
mod transaction;

use std::mem;

pub use pkt::*;

use crate::core::{DnsZoneResolver, QueryResponse};

pub struct DnsIterativeNameserver {
    zone: DnsZoneResolver,
}

impl DnsIterativeNameserver {
    pub fn handle(&self, mut request: DnsMessage) -> DnsMessage {
        assert!(!request.qr, "0 = request");
        // DB tick

        let mut questions = Vec::new();
        mem::swap(&mut questions, &mut request.response.questions);

        let response = questions
            .into_iter()
            .map(|question| self.zone.query(question))
            .reduce(|a, b| a.merged(b))
            .expect("no questions");

        self.response_for_request(&request, false, response)
    }

    fn response_for_request(
        &self,
        req: &DnsMessage,
        ra: bool,
        response: QueryResponse,
    ) -> DnsMessage {
        DnsMessage {
            transaction: req.transaction,
            qr: true,
            opcode: DnsOpCode::Query,
            aa: true,
            tc: false,
            rd: req.rd,
            ra,
            rcode: DnsResponseCode::NoError,

            response,
        }
    }
}
