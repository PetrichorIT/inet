use std::{io, net::Ipv6Addr, time::Duration};

use types::ip::Ipv6Prefix;

use crate::{
    IOContext,
    env::RoutingPort,
    interface::{InterfaceDef, NetworkDevice},
    ioctx,
};

use super::cfg::{RouterInterfaceConfiguration, RouterPrefix};

pub fn setup_router(
    addr: Ipv6Addr,
    ports: Vec<RoutingPort>,
    prefixes: Vec<Ipv6Prefix>,
) -> io::Result<()> {
    for port in ports {
        let mut iface = InterfaceDef::new(
            &format!("en-{}", port.output.str()),
            NetworkDevice::from(port),
        )
        .ip(addr.into())
        .ipv6_link_local();

        iface.flags.router = true;
        ioctx().add_interface(iface)?;
    }

    IOContext::failable_api(|ctx| {
        ctx.ipv6.is_router = true;

        let ifids = ctx.ifaces.keys().cloned().collect::<Vec<_>>();
        for ifid in ifids {
            ctx.ipv6.router_cfg.insert(
                ifid,
                RouterInterfaceConfiguration {
                    is_router: true,
                    adv_send_advertisments: true,
                    min_rtr_adv_interval: Duration::from_secs(3),
                    max_rtr_adv_interval: Duration::from_secs(3),
                    adv_managed_flag: false,
                    adv_other_config_flag: false,
                    adv_link_mtu: 1500,
                    adv_reachable_time: Duration::from_secs(90),
                    adv_retrans_time: Duration::from_secs(90),
                    adv_current_hop_limit: 255,
                    adv_default_lifetime: Duration::from_secs(9000),
                    adv_prefix_list: prefixes
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
    })
}
