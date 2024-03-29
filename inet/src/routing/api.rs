use std::{
    io::{self, Error, ErrorKind},
    net::IpAddr,
};

use super::{FwdEntryV4, Ipv4Gateway, RoutingTableId};
use crate::IOContext;

/// Sets the default routing gateway for the entire node.
pub fn set_default_gateway(ip: impl Into<IpAddr>) -> io::Result<()> {
    IOContext::failable_api(|ctx| ctx.set_default_gateway(ip.into()))
}

/// Adds a routing entry to the routing tables.
pub fn add_routing_entry(
    addr: impl Into<IpAddr>,
    mask: impl Into<IpAddr>,
    gw: impl Into<IpAddr>,
    interface: &str,
) -> io::Result<()> {
    IOContext::failable_api(|ctx| {
        ctx.add_routing_entry(
            addr.into(),
            mask.into(),
            gw.into(),
            interface,
            RoutingTableId::DEFAULT,
        )
    })
}

#[must_use]
pub fn add_routing_table() -> io::Result<RoutingTableId> {
    IOContext::failable_api(|ctx| ctx.add_routing_table())
}

pub fn add_routing_entry_to(
    addr: impl Into<IpAddr>,
    mask: impl Into<IpAddr>,
    gw: impl Into<IpAddr>,
    interface: &str,
    table_id: RoutingTableId,
) -> io::Result<()> {
    IOContext::failable_api(|ctx| {
        ctx.add_routing_entry(addr.into(), mask.into(), gw.into(), interface, table_id)
    })
}

/// Returns the contents of the routing table
pub fn route() -> io::Result<Vec<FwdEntryV4>> {
    IOContext::failable_api(|ctx| Ok(ctx.route()))
}

impl IOContext {
    fn route(&mut self) -> Vec<FwdEntryV4> {
        self.ipv4_fwd.entries()
    }

    fn set_default_gateway(&mut self, ip: IpAddr) -> io::Result<()> {
        let Some(iface) = self.ifaces.values().find(|iface| {
            iface
                .addrs
                .iter()
                .any(|addr| addr.matches_ip_subnet(ip))
        }) else {
            return Err(Error::new(
                ErrorKind::Other,
                "gateway not found on any local subnet"
            ))
        };

        match ip {
            IpAddr::V4(ip) => self
                .ipv4_fwd
                .set_default_gw(Ipv4Gateway::Gateway(ip), iface.name.clone()),
            IpAddr::V6(_) => todo!(),
        }

        Ok(())
    }

    fn add_routing_entry(
        &mut self,
        subnet: IpAddr,
        mask: IpAddr,
        gw: IpAddr,
        interface: &str,
        table_id: RoutingTableId,
    ) -> io::Result<()> {
        // Defines a route to a subnet via a gateway and a defined interface

        let Some(iface) = self.ifaces.values().find(|iface| {
            iface
                .name.name == interface
        }) else {
            // dbg!(interface);
            // dbg!(self.ifaces.values());
            return Err(Error::new(
                ErrorKind::Other,
                "interface not found"
            ))
        };

        use IpAddr::{V4, V6};
        match (subnet, mask, gw) {
            (V4(dest), V4(mask), V4(gw)) => {
                self.ipv4_fwd.add_entry(
                    FwdEntryV4 {
                        dest,
                        mask,
                        gateway: Ipv4Gateway::Gateway(gw),
                        iface: iface.name.clone(),
                    },
                    table_id,
                );
            }
            (V6(_dest), V6(_mask), V6(_gw)) => {
                todo!()
            }
            _ => unreachable!(),
        }

        Ok(())
    }

    fn add_routing_table(&mut self) -> io::Result<RoutingTableId> {
        self.ipv4_fwd.add_table()
    }
}
