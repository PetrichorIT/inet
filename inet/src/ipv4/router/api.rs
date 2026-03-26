use std::{
    io::{self, Error},
    net::Ipv4Addr,
};

use crate::{IOContext, IOHandle, ioctx};

use super::{FwdEntryV4, Ipv4Gateway, RoutingTableId};

/// Sets the default routing gateway for the entire node.
pub fn set_default_gateway(ip: Ipv4Addr) -> io::Result<()> {
    ioctx().set_default_gateway(ip)
}

/// Adds a routing entry to the routing tables.
pub fn add_routing_entry(
    addr: Ipv4Addr,
    mask: Ipv4Addr,
    gw: Ipv4Addr,
    interface: &str,
) -> io::Result<()> {
    add_routing_entry_to(addr, mask, gw, interface, RoutingTableId::DEFAULT)
}

pub fn add_routing_entry_to(
    addr: Ipv4Addr,
    mask: Ipv4Addr,
    gw: Ipv4Addr,
    interface: &str,
    table: RoutingTableId,
) -> io::Result<()> {
    ioctx().add_routing_entry_to(addr, mask, gw, interface, table)
}

pub fn add_routing_table() -> io::Result<RoutingTableId> {
    ioctx().add_routing_table()
}

pub fn route() -> io::Result<Vec<FwdEntryV4>> {
    ioctx().route()
}

impl IOHandle {
    pub fn set_default_gateway(&self, ip: Ipv4Addr) -> io::Result<()> {
        self.do_mutating_on_active_module(|ctx| ctx.set_default_gateway(ip))
    }

    pub fn add_routing_entry_to(
        &self,
        addr: Ipv4Addr,
        mask: Ipv4Addr,
        gw: Ipv4Addr,
        interface: &str,
        table: RoutingTableId,
    ) -> io::Result<()> {
        self.do_mutating_on_active_module(|ctx| {
            ctx.add_routing_entry(addr, mask, gw, interface, table)
        })
    }

    pub fn add_routing_table(&self) -> io::Result<RoutingTableId> {
        self.do_mutating_on_active_module(|ctx| ctx.add_routing_table())
    }

    pub fn route(&self) -> io::Result<Vec<FwdEntryV4>> {
        self.do_readonly(|ctx| Ok(ctx.route()))
    }
}

impl IOContext {
    fn set_default_gateway(&mut self, ip: Ipv4Addr) -> io::Result<()> {
        let Some(iface) = self
            .ifaces
            .values()
            .find(|iface| iface.bindings.v4.matches_subnet(ip))
        else {
            return Err(Error::other("gateway not found on any local subnet"));
        };

        self.ipv4
            .fwd
            .set_default_gw(Ipv4Gateway::Gateway(ip), iface.name.clone());

        Ok(())
    }

    fn add_routing_entry(
        &mut self,
        dest: Ipv4Addr,
        mask: Ipv4Addr,
        gw: Ipv4Addr,
        interface: &str,
        table_id: RoutingTableId,
    ) -> io::Result<()> {
        // Defines a route to a subnet via a gateway and a defined interface

        let Some(iface) = self
            .ifaces
            .values()
            .find(|iface| iface.name.name == interface)
        else {
            // dbg!(interface);
            // dbg!(self.ifaces.values());
            return Err(Error::other("interface not found"));
        };

        self.ipv4.fwd.add_entry(
            FwdEntryV4 {
                dest,
                mask,
                gateway: Ipv4Gateway::Gateway(gw),
                iface: iface.name.clone(),
            },
            table_id,
        );

        Ok(())
    }

    fn route(&self) -> Vec<FwdEntryV4> {
        self.ipv4.fwd.entries()
    }

    fn add_routing_table(&mut self) -> io::Result<RoutingTableId> {
        self.ipv4.fwd.add_table()
    }
}
