use std::time::Duration;

pub struct InterfaceState {
    pub link_mtu: u32,
    pub cur_hop_limit: u8,
    pub base_reachable_time: Duration,
    pub reachable_time: Duration,
    pub retrans_timer: Duration,
}
