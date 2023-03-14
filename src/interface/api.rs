use std::{
    io::{self, Error, ErrorKind},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use des::{prelude::module_name, time::SimTime};

use super::{Interface, InterfaceAddr, MacAddress};
use crate::{
    arp::ARPEntryInternal,
    routing::{Ipv4Gateway, Ipv6Gateway},
    IOContext,
};

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
            if !iface.flags.loopback && iface.flags.broadcast {
                if iface.ipv4_subnet().is_some() {
                    let _ = self.arp.add(ARPEntryInternal {
                        hostname: None,
                        ip: IpAddr::V4(Ipv4Addr::BROADCAST),
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

                if iface.ipv6_subnet().is_some() {
                    let _ = self.arp.add(ARPEntryInternal {
                        hostname: None,
                        ip: IpAddr::V6(Ipv6Addr::new(0xf801, 0, 0, 0, 0, 0, 0, 1)),
                        mac: MacAddress::BROADCAST,
                        iface: iface.name.id,
                        expires: SimTime::MAX,
                    });

                    self.ipv6router.add_entry(
                        Ipv6Addr::new(0xf801, 0, 0, 0, 0, 0, 0, 1),
                        Ipv6Addr::new(
                            0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff,
                        ),
                        Ipv6Gateway::Broadcast,
                        iface.name.id,
                        usize::MAX,
                    );
                }
            }

            // (1) Add all interface addrs to ARP
            for addr in &iface.addrs {
                match addr {
                    InterfaceAddr::Inet { addr, .. } => {
                        let _ = self.arp.add(ARPEntryInternal {
                            hostname: Some(module_name()),
                            ip: IpAddr::V4(*addr),
                            mac: iface.device.addr,
                            iface: iface.name.id,
                            expires: SimTime::MAX,
                        });
                    }
                    InterfaceAddr::Inet6 { addr, .. } => {
                        let _ = self.arp.add(ARPEntryInternal {
                            hostname: Some(module_name()),
                            ip: IpAddr::V6(*addr),
                            mac: iface.device.addr,
                            iface: iface.name.id,
                            expires: SimTime::MAX,
                        });
                    }
                    _ => todo!(),
                }
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

            // (3) Add interface subnet to routing table.
            if let Some((addr, mask)) = iface.ipv6_subnet() {
                self.ipv6router.add_entry(
                    addr,
                    mask,
                    Ipv6Gateway::Local,
                    iface.name.id,
                    usize::MAX / 4,
                )
            }

            self.ifaces.insert(iface.name.id, iface);
            Ok(())
        }
    }
}
