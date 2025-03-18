use std::{
    io::{self, Error, ErrorKind},
    net::Ipv4Addr,
};

use crate::IOContext;

use super::{FwdEntryV4, Ipv4Gateway, Ipv6RouterConfig, RoutingTableId};

pub fn declare_ipv6_router(cfg: Ipv6RouterConfig) -> io::Result<()> {
    IOContext::failable_api(|ctx| ctx.declare_ipv6_router(cfg))
}

/// Sets the default routing gateway for the entire node.
pub fn set_default_gateway(ip: Ipv4Addr) -> io::Result<()> {
    IOContext::failable_api(|ctx| ctx.set_default_gateway(ip))
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
    IOContext::failable_api(|ctx| ctx.add_routing_entry(addr, mask, gw, interface, table))
}

#[must_use]
pub fn add_routing_table() -> io::Result<RoutingTableId> {
    IOContext::failable_api(|ctx| ctx.add_routing_table())
}

pub fn route() -> io::Result<Vec<FwdEntryV4>> {
    IOContext::failable_api(|ctx| Ok(ctx.route()))
}

impl IOContext {
    fn set_default_gateway(&mut self, ip: Ipv4Addr) -> io::Result<()> {
        let Some(iface) = self
            .ifaces
            .values()
            .find(|iface| iface.bindings.v4.matches(ip))
        else {
            return Err(Error::new(
                ErrorKind::Other,
                "gateway not found on any local subnet",
            ));
        };

        self.ipv4_fwd
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
            return Err(Error::new(ErrorKind::Other, "interface not found"));
        };

        self.ipv4_fwd.add_entry(
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

    fn route(&mut self) -> Vec<FwdEntryV4> {
        self.ipv4_fwd.entries()
    }

    fn add_routing_table(&mut self) -> io::Result<RoutingTableId> {
        self.ipv4_fwd.add_table()
    }
}
