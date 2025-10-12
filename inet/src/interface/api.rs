use super::{IfId, InterfaceAddrsV6, MacAddress, def::InterfaceDef};
use crate::{
    IOContext, IOHandle,
    interface::{InterfaceAddrV4, InterfaceAddrV6, InterfaceEvent, InterfaceHandle},
    ipv4::{
        arp::ArpEntryInternal,
        router::{FwdEntryV4, Ipv4Gateway, RoutingTableId},
    },
    ipv6::{multicast::NodeEvent, ndp::QueryType},
};
use des::{net::module::current, time::SimTime};
use std::{
    io::{self, Error, ErrorKind},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};
use tracing::Level;
use types::ip::Ipv6AddrExt;

impl IOHandle {
    /// Creates a new network interface from an interface definition.
    /// Returns a handle to the newly created interface.
    ///
    /// # Errors
    ///
    /// This function may fail if:
    /// - an interface with the same name already exists.
    /// - a requested address cannot be supported
    /// - a misconfiguration is present
    ///
    pub fn add_interface(&self, iface: InterfaceDef) -> io::Result<InterfaceHandle> {
        self.do_failable(|ctx| ctx.add_interface(iface))
    }

    /// Retrieves a handle to an existing interface, based on its name.
    ///
    /// # Errors
    ///
    /// This function may fail if no interface with the given name exists.
    pub fn get_interface(&self, desc: &str) -> io::Result<InterfaceHandle> {
        self.get_interface_by_ifid(IfId::new(desc))
    }

    /// Retrieves a handle to an existing interface, based on its id.
    ///
    /// # Errors
    ///
    /// This function may fail if no interface with the given id exists.
    pub fn get_interface_by_ifid(&self, id: IfId) -> io::Result<InterfaceHandle> {
        let rx = self
            .do_io(|ctx| ctx.ifaces.get(&id).map(|v| v.state.events.subscribe()))
            .ok_or_else(|| Error::new(ErrorKind::NotFound, "no such interface exists"))?;

        Ok(InterfaceHandle {
            io: self.clone(),
            id,
            rx,
        })
    }
}

impl IOContext {
    pub fn add_interface(&mut self, def: InterfaceDef) -> io::Result<InterfaceHandle> {
        let iface = def.into_legacy();
        let ifid = iface.name.id();

        if self.ifaces.contains_key(&iface.name.id()) {
            // FIXME: this error can occur even if name1 != name2, but id == id (hash collision)
            return Err(Error::other(format!(
                "cannot duplicate interface with name {}",
                iface.name
            )));
        }

        // TODO: check nondup
        self.meta_changed |= true;

        let v4 = iface.ipv4_subnet().is_some();
        let v6 = iface.ipv6_subnet().is_some() || iface.flags.v6;

        // (0) Check if the iface can be used as a valid broadcast target.
        if !iface.flags.loopback && iface.flags.broadcast && v4 {
            let _ = self.ipv4.arp.update(ArpEntryInternal {
                negated: false,
                hostname: None,
                ip: Ipv4Addr::BROADCAST,
                mac: MacAddress::BROADCAST,
                iface: iface.name.id(),
                expires: SimTime::MAX,
            });

            self.ipv4.fwd.add_entry(
                FwdEntryV4::broadcast(iface.name.clone()),
                RoutingTableId::DEFAULT,
            );
        }

        // (1) Add all interface addrs to ARP
        for addr in iface.bindings.addrs() {
            match addr {
                IpAddr::V4(binding) => {
                    let _ = self.ipv4.arp.update(ArpEntryInternal {
                        negated: false,
                        hostname: Some(current().name()),
                        ip: binding,
                        mac: iface.device.addr,
                        iface: iface.name.id(),
                        expires: SimTime::MAX,
                    });
                }
                IpAddr::V6(_) => {}
            }
        }

        // (2) Add interface subnet to routing table.
        if let Some((addr, mask)) = iface.ipv4_subnet() {
            // TODO: Maybe this needs to be added allways, but lets try to restrict to LANs
            if !mask.is_unspecified() {
                self.ipv4.fwd.add_entry(
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

        let router = iface.flags.router;
        let loopback = iface.flags.loopback;
        let mac = iface.device.addr;

        let mut iface = iface;
        let mut addrs = InterfaceAddrsV6::default();
        std::mem::swap(&mut addrs, &mut iface.bindings.v6);

        let rx = iface.state.events.subscribe();

        iface.status().publish();
        self.ifaces.insert(iface.name.id(), iface);

        if v6 && !router && !loopback {
            // Autocfg a link local address;
            if !addrs.unicast.iter().any(|addr| addr.addr.is_link_local()) {
                // Link-local address generation
                // RFC 4862 says that this addr should be generated, when
                // - interface starts up
                // - interface device attached, for the first time (may be future feature)
                // - enabled after disabled (assuming that addr is not allready bound)

                let binding = InterfaceAddrV6::new_link_local(mac);
                self.interface_add_addr_v6(ifid, binding, false)?;
            }

            // TODO: legacy impl improve
            for binding in addrs.unicast {
                // Force no dedup
                self.interface_add_addr_v6(ifid, binding, true)?;
            }

            self.ipv6_register_host_interface(ifid)?;
        } else {
            for binding in addrs.unicast {
                self.interface_add_addr_v6(ifid, binding, true)?;
            }
        }

        if v6 && router {
            self.ipv6_schedule_unsolicited_router_adv(ifid)?;
        }

        self.ifaces.get(&ifid).unwrap().status().publish();

        Ok(InterfaceHandle {
            id: ifid,
            io: self.handle(),
            rx,
        })
    }

    pub fn interface_add_addr(&mut self, name: &str, addr: IpAddr) -> io::Result<()> {
        match addr {
            IpAddr::V4(addr) => {
                let Some((ifid, iface)) = self
                    .ifaces
                    .iter_mut()
                    .find(|(_, iface)| &*iface.name == name)
                else {
                    todo!()
                };

                let _guard = tracing::span!(Level::INFO, "iface", id = %ifid).entered();

                tracing::debug!("assigning blind address {addr}");
                iface.bindings.v4.add(InterfaceAddrV4 {
                    addr,
                    mask: Ipv4Addr::BROADCAST,
                });

                iface.status().publish();
                Ok(())
            }
            IpAddr::V6(addr) => {
                let binding = InterfaceAddrV6::new_static(addr, 64);
                let ifid = self
                    .ifaces
                    .keys()
                    .find(|key| key.matches(name))
                    .cloned()
                    .unwrap();
                self.interface_add_addr_v6(ifid, binding, false)
            }
        }
    }

    pub fn interface_add_addr_v6(
        &mut self,
        ifid: IfId,
        binding: InterfaceAddrV6,
        no_dedup: bool,
    ) -> io::Result<()> {
        let Some(iface) = self.ifaces.get_mut(&ifid) else {
            todo!()
        };
        let _guard = tracing::span!(Level::INFO, "iface", id=%ifid).entered();

        if !iface.flags.multicast {
            tracing::debug!("assigning blind address '{binding}'");
            iface.bindings.v6.add(binding);
            iface.status().publish();
            return Ok(());
        }

        if self.ipv6.cfg.dup_addr_detect_transmits > 0 && !no_dedup {
            tracing::debug!(%binding, "initiating tentative address checks");

            self.ipv6_icmp_send_neighbor_solicitation(
                binding.addr,
                ifid,
                QueryType::TentativeAddressCheck(binding),
            )
        } else {
            iface.bindings.v6.join(Ipv6Addr::MULTICAST_ALL_NODES);
            if iface.flags.router {
                iface.bindings.v6.join(Ipv6Addr::MULTICAST_ALL_ROUTERS);
            }

            let multicast = Ipv6Addr::solicied_node_multicast(binding.addr);

            let needs_mld_report = iface.bindings.v6.join(multicast);
            let event = InterfaceEvent::AddrUp(binding.addr.into());
            iface.bindings.v6.add(binding);
            iface.state.events.send_replace(event);

            iface.status().publish();
            if needs_mld_report {
                self.mld_on_event(ifid, NodeEvent::StartListening, multicast)?;
            }
            Ok(())
        }
    }
}
