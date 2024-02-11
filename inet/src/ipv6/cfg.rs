use std::time::Duration;

use inet_types::ip::Ipv6Prefix;

#[derive(Debug, Clone)]
pub struct HostConfiguration {
    pub dup_addr_detect_transmits: usize, // The number of solicitations neeed, to confirm the uniqueness of an address
}

impl Default for HostConfiguration {
    fn default() -> Self {
        Self {
            dup_addr_detect_transmits: 1,
        }
    }
}

#[derive(Debug, Clone)]
pub struct RouterInterfaceConfiguration {
    pub is_router: bool,
    pub adv_send_advertisments: bool,
    pub min_rtr_adv_interval: Duration,
    pub max_rtr_adv_interval: Duration,
    pub adv_managed_flag: bool,
    pub adv_other_config_flag: bool,
    pub adv_link_mtu: u32,
    pub adv_reachable_time: Duration,
    pub adv_retrans_time: Duration,
    pub adv_current_hop_limit: u8,
    pub adv_default_lifetime: Duration,
    pub adv_prefix_list: Vec<RouterPrefix>,

    pub allow_solicited_advertisments_unicast: bool,
}

#[derive(Debug, Clone)]
pub struct RouterPrefix {
    pub prefix: Ipv6Prefix,
    pub on_link: bool,
    pub autonomous: bool,
    pub valid_lifetime: Duration,
    pub preferred_lifetime: Duration,
}
