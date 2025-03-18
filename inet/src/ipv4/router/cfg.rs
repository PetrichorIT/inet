use std::time::Duration;

use types::ip::Ipv6Prefix;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Ipv6RouterConfig {
    pub adv: bool,
    pub current_hop_limit: u8,
    pub managed: bool,
    pub other_cfg: bool,
    pub lifetime: Duration,
    pub reachable_time: Duration,
    pub retransmit_time: Duration,
    pub prefixes: Vec<Ipv6Prefix>,
}

impl Default for Ipv6RouterConfig {
    fn default() -> Self {
        Self {
            adv: true,
            current_hop_limit: 64,
            managed: false,
            other_cfg: false,
            lifetime: Duration::from_secs(9000),
            reachable_time: Duration::from_secs(9000),
            retransmit_time: Duration::from_secs(9000),
            prefixes: Vec::new(),
        }
    }
}
