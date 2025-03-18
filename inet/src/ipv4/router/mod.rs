use crate::{
    ipv6::cfg::{RouterInterfaceConfiguration, RouterPrefix},
    IOContext,
};
use std::{io, time::Duration};

mod api;
mod cfg;
mod table;

pub use api::*;
pub use cfg::*;
pub use table::*;

impl IOContext {
    pub fn declare_ipv6_router(&mut self, cfg: Ipv6RouterConfig) -> io::Result<()> {
        self.ipv6.is_router = true;
        let ifids = self.ifaces.keys().cloned().collect::<Vec<_>>();
        for ifid in ifids {
            self.ipv6.router_cfg.insert(
                ifid,
                RouterInterfaceConfiguration {
                    is_router: true,
                    adv_send_advertisments: cfg.adv,
                    min_rtr_adv_interval: Duration::from_secs(3),
                    max_rtr_adv_interval: Duration::from_secs(3),
                    adv_managed_flag: cfg.managed,
                    adv_other_config_flag: cfg.other_cfg,
                    adv_link_mtu: 1500,
                    adv_reachable_time: cfg.reachable_time,
                    adv_retrans_time: cfg.retransmit_time,
                    adv_current_hop_limit: cfg.current_hop_limit,
                    adv_default_lifetime: cfg.lifetime,
                    adv_prefix_list: cfg
                        .prefixes
                        .iter()
                        .map(|p| RouterPrefix {
                            prefix: *p,
                            on_link: true,
                            autonomous: true,
                            valid_lifetime: Duration::from_secs(9000),
                            preferred_lifetime: Duration::from_secs(5000),
                        })
                        .collect(),
                    allow_solicited_advertisments_unicast: false,
                },
            );
        }
        Ok(())
    }
}
