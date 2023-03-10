use std::{
    io::{self, Error, ErrorKind},
    net::{IpAddr, Ipv4Addr},
};

use super::{Ipv4Gateway, Ipv4RoutingTableEntry};
use crate::IOContext;

pub fn set_default_gateway(ip: Ipv4Addr) -> io::Result<()> {
    IOContext::try_with_current(|ctx| ctx.set_default_gateway(ip))
        .ok_or(Error::new(ErrorKind::Other, "missing IO Context"))?
}

pub fn add_routing_entry(addr: Ipv4Addr, mask: Ipv4Addr, gw: Ipv4Addr) -> io::Result<()> {
    IOContext::try_with_current(|ctx| ctx.add_routing_entry(addr, mask, gw))
        .ok_or(Error::new(ErrorKind::Other, "missing IO Context"))?
}

pub fn route() -> io::Result<Vec<Ipv4RoutingTableEntry>> {
    IOContext::try_with_current(|ctx| ctx.route())
        .ok_or(Error::new(ErrorKind::Other, "missing IO Context"))
}

impl IOContext {
    pub fn route(&mut self) -> Vec<Ipv4RoutingTableEntry> {
        self.ipv4router.entries.clone()
    }

    pub fn set_default_gateway(&mut self, ip: Ipv4Addr) -> io::Result<()> {
        let Some(iface) = self.ifaces.values().find(|iface| {
            iface
                .addrs
                .iter()
                .any(|addr| addr.matches_ip_subnet(IpAddr::V4(ip)))
        }) else {
            return Err(Error::new(
                ErrorKind::Other,
                "gateway cannot be on any local subnet"
            ))
        };

        self.ipv4router.add_entry(
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Gateway::Gateway(ip),
            iface.name.id,
            usize::MAX / 2,
        );
        Ok(())
    }

    pub fn add_routing_entry(
        &mut self,
        addr: Ipv4Addr,
        mask: Ipv4Addr,
        gw: Ipv4Addr,
    ) -> io::Result<()> {
        let Some(iface) = self.ifaces.values().find(|iface| {
            iface
                .addrs
                .iter()
                .any(|addr| addr.matches_ip_subnet(IpAddr::V4(gw)))
        }) else {
            return Err(Error::new(
                ErrorKind::Other,
                "gateway cannot be on any local subnet"
            ))
        };

        self.ipv4router
            .add_entry(addr, mask, Ipv4Gateway::Gateway(gw), iface.name.id, 1);
        Ok(())
    }
}
