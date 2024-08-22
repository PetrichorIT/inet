use std::net::IpAddr;

use crate::core::DnsQuestion;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsNameserverQuery {
    pub nameserver_ip: IpAddr,
    pub transaction: u16,
    pub question: DnsQuestion,
}
