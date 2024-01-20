use std::{net::Ipv6Addr, time::Duration};

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
    pub prefix_len: u8,
    pub prefix: Ipv6Addr,
    pub on_link: bool,
    pub autonomous: bool,
    pub valid_lifetime: Duration,
    pub preferred_lifetime: Duration,
}
