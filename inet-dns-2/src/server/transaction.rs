use crate::core::{Error, NsResourceRecord, QueryResponse, Question};
use des::time::SimTime;
use std::{
    fmt::Display,
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceQuery {
    pub medium: TransportMedium,
    pub addr: SocketAddr,
    pub transaction: u16,
    pub question: Question,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TransportMedium {
    Local,
    Udp,
    Tcp,
}

impl TransportMedium {
    pub fn fallback(self) -> Option<Self> {
        match self {
            Self::Local => Some(Self::Udp),
            Self::Tcp => Some(Self::Udp),
            Self::Udp => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveTransaction {
    // source request
    pub query: Arc<SourceQuery>,

    pub operation_counter: usize,

    // request info
    pub local_transaction: u16,
    pub remote: Vec<(NsResourceRecord, IpAddr)>,
    pub deadline: SimTime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NameserverQuery {
    pub query: Arc<SourceQuery>,
    pub transaction: u16,
    pub nameserver_ip: IpAddr,
}

#[derive(Debug, PartialEq, Eq)]
pub struct FinishedTransaction {
    pub query: Arc<SourceQuery>,
    pub result: TransactionResult,
}

#[derive(Debug, PartialEq, Eq)]
pub enum TransactionResult {
    Success(QueryResponse),
    Failure(Error),
}

impl Display for SourceQuery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:?}:{}/{} {}",
            self.medium, self.addr, self.transaction, self.question
        )
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
