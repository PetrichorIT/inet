use crate::core::{DnsQuestion, NsResourceRecord, QueryResponse};
use des::time::SimTime;
use std::net::SocketAddr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsTransaction {
    pub client: SocketAddr,
    pub client_transaction: u16,
    pub local_transaction: u16,

    pub question: DnsQuestion,
    pub remote: Option<NsResourceRecord>,

    pub operation_counter: usize,

    pub deadline: SimTime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsFinishedTransaction {
    pub client: SocketAddr,
    pub question: DnsQuestion,
    pub response: QueryResponse,
}

impl DnsTransaction {
    pub fn id(&self) -> String {
        format!("{}'{}", self.local_transaction, self.operation_counter)
    }
}
