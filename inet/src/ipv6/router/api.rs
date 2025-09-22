use std::{io, net::Ipv6Addr, time::Duration};

use des::time::SimTime;
use types::{
    iface::MacAddress,
    ip::{Ipv6AddrExt, Ipv6Prefix},
};

use crate::{
    ctx::IOContext,
    interface::{DEFAULT_V6_MASK, IfId, InterfaceDef, NetworkDevice},
    ipv6::cfg::{RouterInterfaceConfiguration, RouterPrefix},
};

pub fn declare_router() -> io::Result<()> {
    IOContext::failable_api(|ctx| ctx.ipv6_router_declare_router())
}

pub fn add_routing_interface(
    name: impl AsRef<str>,
    device: NetworkDevice,
    addrs: &[Ipv6Addr],
    adv: bool,
) -> io::Result<()> {
    IOContext::failable_api(|ctx| ctx.ipv6_router_add_routing_interface(name, device, addrs, adv))
}

pub fn routing_interface_ingore_prefix(
    name: impl AsRef<str>,
    prefix: Ipv6Prefix,
) -> io::Result<()> {
    IOContext::failable_api(|ctx| ctx.routing_interface_ingore_prefix(name, prefix))
}

pub fn add_routing_entry(prefix: Ipv6Prefix, next_hop: Ipv6Addr, via: Ipv6Addr) -> io::Result<()> {
    IOContext::failable_api(|ctx| ctx.ipv6_router_add_routing_entry(prefix, next_hop, via))
}

pub fn add_routing_prefix(prefix: Ipv6Prefix) -> io::Result<()> {
    IOContext::failable_api(|ctx| ctx.ipv6_router_add_routing_prefix(prefix))
}

pub fn add_solicitation_entry(addr: Ipv6Addr, mac: MacAddress, ifid: IfId) -> io::Result<()> {
    IOContext::failable_api(|ctx| {
        ctx.ipv6.neighbors.update(addr, mac, ifid, false);
        ctx.ipv6.neighbors.set_reachable(addr);
        Ok(())
    })
}

impl IOContext {
    fn ipv6_router_declare_router(&mut self) -> io::Result<()> {
        self.ipv6.is_router = true;
        self.ipv6.router_cfg_default = Some(RouterInterfaceConfiguration {
            is_router: true,
            adv_send_advertisments: true,
            min_rtr_adv_interval: Duration::from_secs(3),
            max_rtr_adv_interval: Duration::from_secs(3),
            adv_managed_flag: false,
            adv_other_config_flag: false,
            adv_link_mtu: 1500,
            adv_reachable_time: Duration::from_secs(3000),
            adv_retrans_time: Duration::from_secs(3000),
            adv_current_hop_limit: 32,
            adv_default_lifetime: Duration::from_secs(9000),
            adv_prefix_list: Vec::new(),
            allow_solicited_advertisments_unicast: false,
        });
        Ok(())
    }

    fn ipv6_router_add_routing_interface(
        &mut self,
        name: impl AsRef<str>,
        device: NetworkDevice,
        addrs: &[Ipv6Addr],
        adv: bool,
    ) -> io::Result<()> {
        let mut interface = InterfaceDef::new(name.as_ref(), device);
        let addrs = addrs.into_iter().map(|&addr| {
            if addr == Ipv6Addr::LINK_LOCAL {
                interface.device.addr.embed_into(Ipv6Addr::LINK_LOCAL)
            } else {
                addr
            }
        });

        for addr in addrs {
            interface.addrs.ipv6.push((addr, DEFAULT_V6_MASK))
        }
        interface.flags.router = true;

        let ifid = interface.name.id();

        let Some(mut cfg) = self.ipv6.router_cfg_default.clone() else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "missing router declaration",
            ));
        };

        cfg.adv_send_advertisments = adv;
        self.add_interface(interface)?;
        self.ipv6.router_cfg.insert(ifid, cfg);
        Ok(())
    }

    fn routing_interface_ingore_prefix(
        &mut self,
        name: impl AsRef<str>,
        prefix: Ipv6Prefix,
    ) -> io::Result<()> {
        let ifid = IfId::new(name.as_ref());

        let entry = self
            .ipv6
            .router_cfg
            .get_mut(&ifid)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "Unknown interface"))?;

        entry.adv_prefix_list.retain(|v| v.prefix != prefix);

        Ok(())
    }

    fn ipv6_router_add_routing_entry(
        &mut self,
        prefix: Ipv6Prefix,
        next_hop: Ipv6Addr,
        via: Ipv6Addr,
    ) -> io::Result<()> {
        let ifid = self.ipv6_ifid_for_src_addr(via);
        self.ipv6.neighbors.add_static(next_hop, ifid, true);
        self.ipv6.router.add(
            prefix,
            next_hop,
            ifid,
            SimTime::now() + Duration::from_secs(60),
        );
        Ok(())
    }

    fn ipv6_router_add_routing_prefix(&mut self, prefix: Ipv6Prefix) -> io::Result<()> {
        self.ipv6.prefixes.set_static(prefix);
        if let Some(ref mut cfg) = self.ipv6.router_cfg_default {
            cfg.adv_prefix_list.push(RouterPrefix {
                on_link: true,
                prefix,
                preferred_lifetime: Duration::from_secs(1000),
                valid_lifetime: Duration::from_secs(1000),
                autonomous: true,
            });
        }

        for (_, cfg) in &mut self.ipv6.router_cfg {
            cfg.adv_prefix_list.push(RouterPrefix {
                on_link: true,
                prefix,
                preferred_lifetime: Duration::from_secs(1000),
                valid_lifetime: Duration::from_secs(1000),
                autonomous: true,
            });
        }

        Ok(())
    }
}
