use super::DnsMessage;
use crate::core::{DnsQuestion, DnsResourceRecord};
use des::time::SimTime;
use std::net::{IpAddr, SocketAddr};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsTransaction {
    client: SocketAddr,
    client_req: DnsMessage,
    client_question: DnsQuestion,
    client_transaction: u16,

    local_transaction: u16,
    ns: DnsResourceRecord,
    nsip: IpAddr,

    deadline: SimTime,
}
