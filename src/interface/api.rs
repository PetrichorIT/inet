use std::{
    io::{self, Error, ErrorKind},
    net::Ipv4Addr,
};

use des::{prelude::module_name, time::SimTime};

use super::{Interface, InterfaceAddr, MacAddress};
use crate::{arp::ARPEntryInternal, routing::Ipv4Gateway, IOContext};

pub fn add_interface(iface: Interface) -> io::Result<()> {
    IOContext::with_current(|ctx| ctx.add_interface(iface))
}

impl IOContext {
    pub fn add_interface(&mut self, iface: Interface) -> io::Result<()> {
        if self.ifaces.get(&iface.name.id).is_some() {
            Err(Error::new(
                ErrorKind::Other,
                format!("cannot duplicate interface with name {}", iface.name),
            ))
        } else {
            // TODO: check nondup

            // (0) Check if the iface can be used as a valid broadcast target.
            if !iface.flags.loopback && iface.ipv4_subnet().is_some() {
                let _ = self.arp.add(ARPEntryInternal {
                    hostname: None,
                    ip: Ipv4Addr::BROADCAST,
                    mac: MacAddress::BROADCAST,
                    iface: iface.name.id,
                    expires: SimTime::MAX,
                });

                self.ipv4router.add_entry(
                    Ipv4Addr::BROADCAST,
                    Ipv4Addr::BROADCAST,
                    Ipv4Gateway::Broadcast,
                    iface.name.id,
                    usize::MAX,
                );
            }

            // (1) Add all interface addrs to ARP
            for addr in &iface.addrs {
                let InterfaceAddr::Inet { addr, .. } = addr else {
                    continue;
                };

                let _ = self.arp.add(ARPEntryInternal {
                    hostname: Some(module_name()),
                    ip: *addr,
                    mac: iface.device.addr,
                    iface: iface.name.id,
                    expires: SimTime::MAX,
                });
            }

            // (2) Add interface subnet to routing table.
            if let Some((addr, mask)) = iface.ipv4_subnet() {
                self.ipv4router.add_entry(
                    addr,
                    mask,
                    Ipv4Gateway::Local,
                    iface.name.id,
                    usize::MAX / 4,
                )
            }

            self.ifaces.insert(iface.name.id, iface);
            Ok(())
        }
    }
}
