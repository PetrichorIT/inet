use crate::core::{Error, NsResourceRecord, QueryResponse, Question};
use des::time::SimTime;
use std::{fmt::Display, net::SocketAddr};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveTransaction {
    pub client: SocketAddr,
    pub client_transaction: u16,
    pub local_transaction: u16,
    pub question: Question,
    pub remote: Option<NsResourceRecord>,
    pub operation_counter: usize,
    pub deadline: SimTime,
}

#[derive(Debug, PartialEq, Eq)]
pub struct FinishedTransaction {
    pub transaction: u16,
    pub client: SocketAddr,
    pub question: Question,
    pub result: TransactionResult,
}

#[derive(Debug, PartialEq, Eq)]
pub enum TransactionResult {
    Success(QueryResponse),
    Failure(Error),
}

impl ActiveTransaction {
    pub fn id(&self) -> String {
        format!("{}'{}", self.local_transaction, self.operation_counter)
    }
}

impl Display for TransactionResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Success(resp) => resp.fmt(f),
            Self::Failure(err) => err.fmt(f),
        }
    }
}
