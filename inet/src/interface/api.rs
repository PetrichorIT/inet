use super::{
    IfId, Interface, InterfaceAddr, InterfaceAddrs, InterfaceAddrsV6, InterfaceBusyState,
    InterfaceFlags, InterfaceName, InterfaceStatus, MacAddress,
};
use crate::{
    arp::ArpEntryInternal,
    interface::{InterfaceAddrV4, InterfaceAddrV6},
    ipv6::ndp::QueryType,
    routing::{FwdEntryV4, Ipv4Gateway, Ipv6Gateway, RoutingTableId},
    IOContext,
};
use des::{net::module::current, time::SimTime};
use inet_types::ip::Ipv6AddrExt;
use std::{
    io::{Error, ErrorKind, Result},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

/// Declares and activiates an new network interface on the current module
pub fn add_interface(iface: Interface) -> Result<()> {
    IOContext::failable_api(|ctx| ctx.add_interface(iface))
}

pub fn interface_add_addr(iface: impl AsRef<str>, addr: IpAddr) -> Result<()> {
    IOContext::failable_api(|ctx| ctx.interface_add_addr(iface.as_ref(), addr))
}

pub fn interface_status(iface: impl AsRef<str>) -> Result<InterfaceState> {
    IOContext::failable_api(|ctx| ctx.interface_status(iface.as_ref()))
}

pub fn interface_status_by_ifid(ifid: IfId) -> Result<InterfaceState> {
    IOContext::failable_api(|ctx| ctx.interface_status_by_ifid(ifid))
}

pub struct InterfaceState {
    pub name: InterfaceName,
    pub flags: InterfaceFlags,
    pub addrs: InterfaceAddrs,
    pub status: InterfaceStatus,
    pub busy: InterfaceBusyState,
    pub queuelen: usize,
}

impl IOContext {
    pub fn add_interface(&mut self, mut iface: Interface) -> Result<()> {
        if self.ifaces.get(&iface.name.id).is_some() {
            return Err(Error::new(
                ErrorKind::Other,
                format!("cannot duplicate interface with name {}", iface.name),
            ));
        }

        // TODO: check nondup
        self.meta_changed |= true;

        let v4 = iface.ipv4_subnet().is_some();
        let v6 = iface.ipv6_subnet().is_some() || iface.flags.v6;

        // (0) Check if the iface can be used as a valid broadcast target.
        if !iface.flags.loopback && iface.flags.broadcast {
            if v4 {
                let _ = self.arp.update(ArpEntryInternal {
                    negated: false,
                    hostname: None,
                    ip: IpAddr::V4(Ipv4Addr::BROADCAST),
                    mac: MacAddress::BROADCAST,
                    iface: iface.name.id,
                    expires: SimTime::MAX,
                });

                self.ipv4_fwd.add_entry(
                    FwdEntryV4::broadcast(iface.name.clone()),
                    RoutingTableId::DEFAULT,
                );
            }

            if v6 {
                let _ = self.arp.update(ArpEntryInternal {
                    negated: false,
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
        for addr in iface.addrs.iter() {
            match addr {
                InterfaceAddr::Inet(binding) => {
                    let _ = self.arp.update(ArpEntryInternal {
                        negated: false,
                        hostname: Some(current().name()),
                        ip: IpAddr::V4(binding.addr),
                        mac: iface.device.addr,
                        iface: iface.name.id,
                        expires: SimTime::MAX,
                    });
                }
                InterfaceAddr::Inet6(addr) => {
                    let _ = self.arp.update(ArpEntryInternal {
                        negated: false,
                        hostname: Some(current().name()),
                        ip: IpAddr::V6(addr.addr),
                        mac: iface.device.addr,
                        iface: iface.name.id,
                        expires: SimTime::MAX,
                    });
                }
            }
        }

        // (2) Add interface subnet to routing table.
        if let Some((addr, mask)) = iface.ipv4_subnet() {
            // TODO: Maybe this needs to be added allways, but lets try to restrict to LANs
            if !mask.is_unspecified() {
                self.ipv4_fwd.add_entry(
                    FwdEntryV4 {
                        dest: addr,
                        mask,
                        gateway: Ipv4Gateway::Local,
                        iface: iface.name.clone(),
                    },
                    RoutingTableId::DEFAULT,
                );
            }
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

        let ifid = iface.name.id;
        let router = iface.flags.router;
        let loopback = iface.flags.loopback;
        let mac = iface.device.addr;

        let mut addrs = InterfaceAddrsV6::default();
        std::mem::swap(&mut addrs, &mut iface.addrs.v6);

        self.ifaces.insert(iface.name.id, iface);

        if v6 && !router && !loopback {
            self.ipv6_register_host_interface(ifid)?;

            // Autocfg a link local address;
            if addrs.unicast.is_empty() {
                // Link-local address generation
                // RFC 4862 says that this addr should be generated, when
                // - interface starts up
                // - interface device attached, for the first time (may be future feature)
                // - enabled after disabled (assuming that addr is not allready bound)

                let binding = InterfaceAddrV6::new_link_local(mac);
                tracing::debug!("autoassigning link local addr '{binding}'");
                self.interface_add_addr_v6(ifid, binding, false)?;
            } else {
                // TODO: legacy impl improve
                for binding in addrs.unicast {
                    self.interface_add_addr_v6(ifid, binding, true)?;
                }
            }
        } else {
            for binding in addrs.unicast {
                self.interface_add_addr_v6(ifid, binding, true)?;
            }
        }

        Ok(())
    }

    pub fn interface_add_addr(&mut self, name: &str, addr: IpAddr) -> Result<()> {
        match addr {
            IpAddr::V4(addr) => {
                let Some((ifid, iface)) = self
                    .ifaces
                    .iter_mut()
                    .find(|(_, iface)| &*iface.name == name)
                else {
                    todo!()
                };

                tracing::debug!(IFACE = %ifid, "assigning blind address {addr}");
                iface.addrs.add(InterfaceAddr::Inet(InterfaceAddrV4 {
                    addr,
                    netmask: Ipv4Addr::BROADCAST,
                }));
                Ok(())
            }
            IpAddr::V6(addr) => {
                let binding = InterfaceAddrV6::new_static(addr, 64);
                let ifid = self.ifaces.keys().find(|key| key.matches(name)).unwrap();
                self.interface_add_addr_v6(*ifid, binding, false)
            }
        }
    }

    pub fn interface_add_addr_v6(
        &mut self,
        ifid: IfId,
        binding: InterfaceAddrV6,
        no_dedup: bool,
    ) -> Result<()> {
        let Some(iface) = self.ifaces.get_mut(&ifid) else {
            todo!()
        };

        if !iface.flags.multicast {
            tracing::debug!(IFACE = %ifid, "assigning blind address '{binding}'");
            iface.addrs.add(InterfaceAddr::Inet6(binding));
            return Ok(());
        }

        if self.ipv6.cfg.dup_addr_detect_transmits > 0 && !no_dedup {
            tracing::debug!(IFACE = %ifid, "initiating tentative address checks for '{binding}'");
            self.ipv6_icmp_send_neighbor_solicitation(
                binding.addr,
                ifid,
                QueryType::TentativeAddressCheck(binding),
            )
        } else {
            tracing::debug!(IFACE = %ifid, "assigning address '{binding}'");

            iface.addrs.v6.join(Ipv6Addr::MULTICAST_ALL_NODES);
            if iface.flags.router {
                iface.addrs.v6.join(Ipv6Addr::MULTICAST_ALL_ROUTERS);
            }
            iface
                .addrs
                .v6
                .join(Ipv6Addr::solicied_node_multicast(binding.addr));

            iface.addrs.add(InterfaceAddr::Inet6(binding));

            Ok(())
        }
    }

    fn interface_status(&mut self, iface_name: &str) -> Result<InterfaceState> {
        let Some((_, iface)) = self
            .ifaces
            .iter()
            .find(|iface| &*iface.1.name == iface_name)
        else {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "no such interface exists",
            ));
        };
        Ok(InterfaceState {
            name: iface.name.clone(),
            flags: iface.flags,
            addrs: iface.addrs.clone(),
            status: iface.status,
            busy: iface.state.clone(),
            queuelen: iface.buffer.len(),
        })
    }

    fn interface_status_by_ifid(&mut self, ifid: IfId) -> Result<InterfaceState> {
        let Some(iface) = self.ifaces.get(&ifid) else {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "no such interface exists",
            ));
        };
        Ok(InterfaceState {
            name: iface.name.clone(),
            flags: iface.flags,
            addrs: iface.addrs.clone(),
            status: iface.status,
            busy: iface.state.clone(),
            queuelen: iface.buffer.len(),
        })
    }
}
