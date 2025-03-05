use crate::core::{Error, NsResourceRecord, QueryResponse, Question};
use des::time::SimTime;
use std::{
    fmt::Display,
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

/// The original client query, initiating a transaction in a nameserver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceQuery {
    pub medium: TransportMedium,
    pub addr: SocketAddr,
    pub transaction: u16,
    pub question: Question,
}

/// Represents the medium used for communication between the nameserver and the client.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(usize)]
pub enum TransportMedium {
    Udp = 0,
    Tcp = 1,
    Local = 255,
}

/// Represents the active transaction in a nameserver.
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

/// Represents a query to a nameserver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NameserverQuery {
    pub query: Arc<SourceQuery>,
    pub transaction: u16,
    pub nameserver_ip: IpAddr,
}

/// Represents a finished transaction in a nameserver, that can be send a DNS response to the client.
#[derive(Debug, PartialEq, Eq)]
pub struct FinishedTransaction {
    pub query: Arc<SourceQuery>,
    pub aa: bool,
    pub ra: bool,
    pub result: TransactionResult,
}

/// The valid results of a DNS transaction.
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
