use std::{io, net::Ipv6Addr, time::Duration};

use des::time::SimTime;
use types::{
    iface::MacAddress,
    ip::{Ipv6AddrExt, Ipv6Prefix},
};

use crate::{
    IOHandle,
    ctx::IOContext,
    interface::{DEFAULT_V6_MASK, IfId, InterfaceDef, NetworkDevice},
    ioctx,
    ipv6::cfg::{RouterInterfaceConfiguration, RouterPrefix},
};

pub fn declare_router() -> io::Result<()> {
    ioctx().ipv6_declare_router()
}

pub fn add_routing_interface(
    name: impl AsRef<str>,
    device: NetworkDevice,
    addrs: &[Ipv6Addr],
    adv: bool,
) -> io::Result<()> {
    ioctx().ipv6_add_routing_interface(name, device, addrs, adv)
}

pub fn add_routing_entry(
    prefix: Ipv6Prefix,
    next_hop: Ipv6Addr,
    local_addr: Ipv6Addr,
) -> io::Result<()> {
    ioctx().ipv6_add_routing_entry(prefix, next_hop, local_addr)
}

pub fn add_routing_prefix(name: impl AsRef<str>, prefix: Ipv6Prefix) -> io::Result<()> {
    ioctx().ipv6_add_routing_prefix(name, prefix)
}

pub fn add_solicitation_entry(addr: Ipv6Addr, mac: MacAddress, ifid: IfId) -> io::Result<()> {
    ioctx().ipv6_add_solicitation_entry(addr, mac, ifid)
}

impl IOHandle {
    pub fn ipv6_declare_router(&self) -> io::Result<()> {
        self.do_failable(|ctx| ctx.ipv6_router_declare_router())
    }

    pub fn ipv6_add_routing_interface(
        &self,
        name: impl AsRef<str>,
        device: NetworkDevice,
        addrs: &[Ipv6Addr],
        adv: bool,
    ) -> io::Result<()> {
        self.do_failable(|ctx| ctx.ipv6_router_add_routing_interface(name, device, addrs, adv))
    }

    pub fn ipv6_add_routing_entry(
        &self,
        prefix: Ipv6Prefix,
        next_hop: Ipv6Addr,
        via: Ipv6Addr,
    ) -> io::Result<()> {
        self.do_failable(|ctx| ctx.ipv6_router_add_routing_entry(prefix, next_hop, via))
    }

    pub fn ipv6_add_routing_prefix(
        &self,
        name: impl AsRef<str>,
        prefix: Ipv6Prefix,
    ) -> io::Result<()> {
        self.do_failable(|ctx| ctx.ipv6_router_add_routing_prefix(IfId::new(name.as_ref()), prefix))
    }

    pub fn ipv6_add_solicitation_entry(
        &self,
        addr: Ipv6Addr,
        mac: MacAddress,
        ifid: IfId,
    ) -> io::Result<()> {
        self.do_failable(|ctx| {
            ctx.ipv6.neighbors.update(addr, mac, ifid, false);
            ctx.ipv6.neighbors.set_reachable(addr);
            Ok(())
        })
    }
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
        let addrs = addrs.iter().map(|&addr| {
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

    fn ipv6_router_add_routing_entry(
        &mut self,
        prefix: Ipv6Prefix,
        next_hop: Ipv6Addr,
        local_addr: Ipv6Addr,
    ) -> io::Result<()> {
        let ifid = self.ipv6_ifid_for_src_addr(local_addr);
        self.ipv6.neighbors.add_static(next_hop, ifid, true);
        self.ipv6.router.add(
            prefix,
            next_hop,
            ifid,
            SimTime::now() + Duration::from_secs(60),
        );
        Ok(())
    }

    fn ipv6_router_add_routing_prefix(&mut self, ifid: IfId, prefix: Ipv6Prefix) -> io::Result<()> {
        self.ipv6.prefixes.set_static(prefix);

        let cfg = self
            .ipv6
            .router_cfg
            .get_mut(&ifid)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no such iface"))?;
        cfg.adv_prefix_list.push(RouterPrefix {
            on_link: true,
            prefix,
            preferred_lifetime: Duration::from_secs(1000),
            valid_lifetime: Duration::from_secs(1000),
            autonomous: true,
        });

        Ok(())
    }
}
