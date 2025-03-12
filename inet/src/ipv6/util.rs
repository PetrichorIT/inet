use std::{io, net::Ipv6Addr, time::Duration};

use types::ip::Ipv6Prefix;

use crate::{
    interface::{add_interface, InterfaceDef, NetworkDevice},
    routing::{declare_ipv6_router, Ipv6RouterConfig, RoutingPort},
};

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
        add_interface(iface)?;
    }

    declare_ipv6_router(Ipv6RouterConfig {
        adv: true,
        current_hop_limit: 255,
        managed: false,
        other_cfg: false,
        lifetime: Duration::from_secs(9000),
        reachable_time: Duration::from_secs(90),
        retransmit_time: Duration::from_secs(90),
        prefixes,
    })
    .unwrap();

    Ok(())
}
