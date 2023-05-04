mod pkt;
mod record;
mod string;

use std::net::IpAddr;

pub use self::pkt::*;
pub use self::record::*;
pub use self::string::*;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DNSNodeInformation {
    pub zone: DNSString,
    pub domain_name: DNSString,
    pub ip: IpAddr,
}
