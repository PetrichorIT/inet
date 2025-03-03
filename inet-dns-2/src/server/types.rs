use std::net::IpAddr;

use crate::core::Question;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NameserverQuery {
    pub nameserver_ip: IpAddr,
    pub transaction: u16,
    pub question: Question,
}
