use crate::{
    arp::ArpEntryInternal,
    ctx::IOContext,
    interface::{IfId, Interface, InterfaceAddr},
};
use bytepack::{FromBytestream, ToBytestream};
use des::{runtime::sample, time::SimTime};
use inet_types::{
    icmpv6::{
        IcmpV6MtuOption, IcmpV6NDPOption, IcmpV6NeighborAdvertisment, IcmpV6NeighborSolicitation,
        IcmpV6Packet, IcmpV6PrefixInformation, IcmpV6RouterAdvertisement, IcmpV6RouterSolicitation,
        NDP_MAX_RANDOM_FACTOR, NDP_MAX_RA_DELAY_TIME, NDP_MIN_RANDOM_FACTOR, PROTO_ICMPV6,
    },
    ip::{
        ipv6_solicited_node_multicast, Ipv6Packet, IPV6_LINK_LOCAL, IPV6_MULTICAST_ALL_NODES,
        IPV6_MULTICAST_ALL_ROUTERS,
    },
};
use rand::distributions::Uniform;
use std::{
    io,
    net::{IpAddr, Ipv6Addr},
    time::Duration,
};

impl IOContext {
    pub(crate) fn ipv6_icmp_send_router_solicitation(&mut self, ifid: IfId) -> io::Result<()> {
        let iface = self.get_iface(ifid)?;
        let iface_mac = iface.device.addr;
        let iface_ll = iface
            .link_local_v6()
            .expect("no link local address configured ??");

        tracing::trace!(
            IFACE=%ifid,
            MAC=%iface_mac,
            IP=%iface_ll,
            "registered for stateless autocfg"
        );

        // Send inital router solictation
        let req = IcmpV6RouterSolicitation {
            options: vec![IcmpV6NDPOption::SourceLinkLayerAddress(iface_mac)],
        };
        let msg = IcmpV6Packet::RouterSolicitation(req);
        let pkt = Ipv6Packet {
            traffic_class: 0,
            flow_label: 0,
            next_header: PROTO_ICMPV6,
            hop_limit: 255,
            src: iface_ll,
            dst: IPV6_MULTICAST_ALL_ROUTERS,
            content: msg.to_vec()?,
        };

        self.ipv6_send(pkt, ifid)?;
        // TOOD: timeout

        Ok(())
    }

    pub(crate) fn ipv6_icmp_recv(&mut self, ip: &Ipv6Packet, ifid: IfId) -> io::Result<bool> {
        assert_eq!(ip.next_header, PROTO_ICMPV6);

        // See RFC 4861 :: 6.1.1
        if ip.hop_limit != 255 {
            return Ok(true);
        }

        let Ok(msg) = IcmpV6Packet::read_from_slice(&mut &ip.content[..]) else {
            tracing::error!(
                "received ip-packet with proto=0x58 (icmpv6) but content was no icmpv6-packet"
            );
            return Ok(false);
        };

        match msg {
            IcmpV6Packet::RouterSolicitation(req) => {
                return self.ipv6_icmp_recv_router_solicitation(ip, ifid, req);
            }
            IcmpV6Packet::RouterAdvertisment(adv) => {
                return self.ipv6_icmp_recv_router_advertisment(ip, ifid, adv);
            }
            IcmpV6Packet::NeighborSolicitation(req) => {
                return self.ipv6_icmp_recv_neighbor_solicitation(ip, ifid, req);
            }
            IcmpV6Packet::NeighborAdvertisment(adv) => {
                return self.ipv6_icmp_recv_neighbor_advertisment(ip, ifid, adv);
            }

            _ => {}
        }

        Ok(true)
    }

    fn ipv6_icmp_recv_router_solicitation(
        &mut self,
        ip: &Ipv6Packet,
        ifid: IfId,
        req: IcmpV6RouterSolicitation,
    ) -> io::Result<bool> {
        // See RFC 4861 :: 6.1.1
        if !self.ipv6.is_rooter {
            return Ok(true);
        }

        if ip.src.is_unspecified() {
            // RFC requires there to be not SourceLinkLayerAddr option
            // IF src is ::
            if req
                .options
                .iter()
                .any(|option| matches!(option, IcmpV6NDPOption::SourceLinkLayerAddress(_)))
            {
                return Ok(true);
            }
        }

        if !ip.src.is_unspecified() {
            // Update neigbor cache
            if let Some(mac) = req.options.iter().find_map(|option| {
                if let IcmpV6NDPOption::SourceLinkLayerAddress(mac) = option {
                    Some(*mac)
                } else {
                    None
                }
            }) {
                self.ipv6.neighbors.update(ip.src, mac, ifid, false);
                // TODO: remove this, ARP is not used for Ipv6
                let _ = self.arp.update(ArpEntryInternal {
                    negated: false,
                    hostname: None,
                    ip: ip.src.into(),
                    mac,
                    iface: ifid,
                    expires: SimTime::now() + Duration::from_secs(120),
                });
            }
        }

        let iface = self.ifaces.get(&ifid).unwrap();
        let iface_mac = iface.device.addr;
        let iface_cfg = self.ipv6.router_cfg.get(&ifid).unwrap();

        let iface_effective_addr = iface.effective_addr_for_src(ip.src).unwrap();

        let adv = IcmpV6RouterAdvertisement {
            router_lifetime: iface_cfg.adv_default_lifetime.as_secs() as u16,
            managed: iface_cfg.adv_managed_flag,
            other_configuration: iface_cfg.adv_other_config_flag,
            current_hop_limit: iface_cfg.adv_current_hop_limit,
            reachable_time: iface_cfg.adv_reachable_time.as_millis() as u32,
            retransmit_time: iface_cfg.adv_retrans_time.as_millis() as u32,
            options: {
                let mut options = Vec::with_capacity(3);
                options.push(IcmpV6NDPOption::SourceLinkLayerAddress(iface_mac));
                if iface_cfg.adv_link_mtu != 0 {
                    options.push(IcmpV6NDPOption::Mtu(IcmpV6MtuOption {
                        mtu: iface_cfg.adv_link_mtu,
                    }))
                }
                for entry in &iface_cfg.adv_prefix_list {
                    options.push(IcmpV6NDPOption::PrefixInformation(
                        IcmpV6PrefixInformation {
                            prefix_len: entry.prefix_len,
                            prefix: entry.prefix,
                            on_link: entry.on_link,
                            valid_lifetime: entry.valid_lifetime.as_millis() as u32,
                            preferred_lifetime: entry.preferred_lifetime.as_millis() as u32,
                            autonomous_address_configuration: entry.autonomous,
                        },
                    ));
                }
                options
            },
        };

        let dst_addr = if ip.src.is_unspecified() {
            IPV6_MULTICAST_ALL_NODES
        } else {
            // RFC 4861 defines that we are allowed to just
            // use the multicast address either way
            if iface_cfg.allow_solicited_advertisments_unicast {
                ip.src
            } else {
                IPV6_MULTICAST_ALL_NODES
            }
        };

        let msg = IcmpV6Packet::RouterAdvertisment(adv);
        let ip = Ipv6Packet {
            traffic_class: 0,
            flow_label: 0,
            next_header: PROTO_ICMPV6,
            hop_limit: 255,
            src: iface_effective_addr,
            dst: dst_addr,
            content: msg.to_vec()?,
        };

        // TODO:
        // Delay advertisment response, only send singe adv to multiple solicitations
        let _delay_time = sample(Uniform::new(0.0, NDP_MAX_RA_DELAY_TIME.as_secs_f64()));

        // TODO:
        // Rate limit sendings to MULTICAST:ALLNODES according to NDP_MIN_DELAY_BETWEEN_RAS

        self.ipv6_send(ip, ifid)?;

        Ok(true)
    }

    fn ipv6_icmp_recv_router_advertisment(
        &mut self,
        ip: &Ipv6Packet,
        ifid: IfId,
        adv: IcmpV6RouterAdvertisement,
    ) -> io::Result<bool> {
        if self.ipv6.is_rooter {
            self.ipv6_icmp_router_advertisment_inspect(ip, ifid, adv)?;
            return Ok(true);
        }

        // Add to default router cache
        if adv.router_lifetime != 0 {
            self.ipv6
                .default_routers
                .update(ip.src, Duration::from_secs(adv.router_lifetime as u64));
        }

        let iface_cfg = self.ipv6.iface_state.get_mut(&ifid).unwrap();
        if adv.current_hop_limit != 0 {
            iface_cfg.cur_hop_limit = adv.current_hop_limit;
        }
        if adv.reachable_time != 0 {
            iface_cfg.base_reachable_time = Duration::from_millis(adv.reachable_time as u64);
            let r64 = iface_cfg.base_reachable_time.as_secs_f64();
            iface_cfg.reachable_time = Duration::from_secs_f64(sample(Uniform::new(
                NDP_MIN_RANDOM_FACTOR * r64,
                NDP_MAX_RANDOM_FACTOR * r64,
            )));
        }
        if adv.retransmit_time != 0 {
            iface_cfg.retrans_timer = Duration::from_millis(adv.retransmit_time as u64);
        }

        for option in &adv.options {
            match option {
                IcmpV6NDPOption::SourceLinkLayerAddress(mac) => {
                    self.ipv6.neighbors.update(ip.src, *mac, ifid, true);

                    // TODO: remove this, ARP is not used for Ipv6
                    let _ = self.arp.update(ArpEntryInternal {
                        negated: false,
                        hostname: None,
                        ip: ip.src.into(),
                        mac: *mac,
                        iface: ifid,
                        expires: SimTime::now() + Duration::from_secs(120),
                    });
                }
                IcmpV6NDPOption::Mtu(mtu) => {
                    iface_cfg.link_mtu = mtu.mtu;
                }
                IcmpV6NDPOption::PrefixInformation(info) => {
                    if !info.on_link {
                        continue;
                    }

                    if info.prefix == IPV6_LINK_LOCAL {
                        // link local is silently ignored
                        continue;
                    }

                    let autocfg = self.ipv6.prefixes.update(info);
                    if autocfg {
                        let iface = self.ifaces.get_mut(&ifid).unwrap();
                        let addr = iface.device.addr.embed_into(info.prefix);

                        iface.addrs.add(InterfaceAddr::Inet6 {
                            addr,
                            prefixlen: info.prefix_len as usize,
                            scope_id: None,
                        });

                        // TODO: advertise new address for neighbor discover
                        tracing::trace!(IFACE=%ifid, MAC=%iface.device.addr, "assigned new address: {addr}");
                    }
                }
                _ => {}
            }
        }

        self.ipv6.neighbors.set_router(ip.src);

        // TODO: Remove this is just for debuggin
        self.ipv6_icmp_send_neighbor_solicitation(ip.src, ifid)?;

        Ok(true)
    }

    fn ipv6_icmp_router_advertisment_inspect(
        &mut self,
        _ip: &Ipv6Packet,
        _ifid: IfId,
        _adv: IcmpV6RouterAdvertisement,
    ) -> io::Result<()> {
        // TODO: inspection, log output
        Ok(())
    }

    fn ipv6_icmp_recv_neighbor_solicitation(
        &mut self,
        ip: &Ipv6Packet,
        ifid: IfId,
        req: IcmpV6NeighborSolicitation,
    ) -> io::Result<bool> {
        // Silently discard multicast solicitations
        if req.target.is_multicast() {
            return Ok(true);
        }

        let src_mac_entry = req.options.iter().find_map(|opt| {
            if let IcmpV6NDPOption::SourceLinkLayerAddress(mac) = opt {
                Some(mac)
            } else {
                None
            }
        });

        // Message validation on unspecific IP
        let iface = self.ifaces.get(&ifid).unwrap();
        if ip.src.is_unspecified() {
            if let Some(unicast_addr) = iface.addrs.ipv6_addrs().first() {
                if *unicast_addr != ip.dst {
                    return Ok(true);
                }

                if src_mac_entry.is_some() {
                    return Ok(true);
                }
            }
        }

        if !ip.src.is_unspecified() {
            if let Some(mac) = src_mac_entry {
                self.ipv6.neighbors.update(ip.src, *mac, ifid, false);
            }
        }

        let dst = if ip.src.is_unspecified() {
            IPV6_MULTICAST_ALL_NODES
        } else {
            ip.src
        };

        let adv = IcmpV6NeighborAdvertisment {
            target: req.target,
            router: self.ipv6.is_rooter,
            solicited: !ip.src.is_unspecified(),
            overide: false,
            options: {
                let mut options = Vec::new();
                options.push(IcmpV6NDPOption::TargetLinkLayerAddress(iface.device.addr));
                options
            },
        };
        let msg = IcmpV6Packet::NeighborAdvertisment(adv);
        let pkt = Ipv6Packet {
            traffic_class: 0,
            flow_label: 0,
            next_header: PROTO_ICMPV6,
            hop_limit: 255,
            src: req.target,
            dst,
            content: msg.to_vec()?,
        };

        self.ipv6_send(pkt, ifid)?;
        Ok(true)
    }

    fn ipv6_icmp_send_neighbor_solicitation(&mut self, ip: Ipv6Addr, ifid: IfId) -> io::Result<()> {
        self.ipv6.neighbors.initalize(ip, ifid);

        let iface = self.ifaces.get(&ifid).unwrap();
        let addr = *iface
            .addrs
            .iter()
            .find_map(|addr| {
                if let InterfaceAddr::Inet6 { addr, .. } = addr {
                    Some(addr)
                } else {
                    None
                }
            })
            .unwrap();

        let req = IcmpV6NeighborSolicitation {
            target: ip,
            options: {
                let mut options = Vec::new();
                options.push(IcmpV6NDPOption::SourceLinkLayerAddress(iface.device.addr));
                options
            },
        };
        let msg = IcmpV6Packet::NeighborSolicitation(req);
        let pkt = Ipv6Packet {
            traffic_class: 0,
            flow_label: 0,
            next_header: PROTO_ICMPV6,
            hop_limit: 255,
            src: addr,
            dst: ipv6_solicited_node_multicast(ip),
            content: msg.to_vec()?,
        };

        self.ipv6_send(pkt, ifid)?;
        Ok(())
    }

    fn ipv6_icmp_recv_neighbor_advertisment(
        &mut self,
        ip: &Ipv6Packet,
        ifid: IfId,
        adv: IcmpV6NeighborAdvertisment,
    ) -> io::Result<bool> {
        if adv.target.is_multicast() {
            return Ok(true);
        }

        if ip.dst.is_multicast() {
            if adv.solicited {
                return Ok(true);
            }
        }

        self.ipv6
            .neighbors
            .process(ifid, &adv, &mut self.ipv6.default_routers);

        // TODO: router changes may need to be propagated

        Ok(true)
    }
}

impl Interface {
    fn effective_addr_for_src(&self, query: Ipv6Addr) -> Option<Ipv6Addr> {
        for addr in &*self.addrs {
            if addr.matches_ip_subnet(IpAddr::V6(query)) {
                let InterfaceAddr::Inet6 { addr, .. } = addr else {
                    unreachable!()
                };
                return Some(*addr);
            }
        }
        dbg!(
            query.octets(),
            "fe80::abcd".parse::<Ipv6Addr>().unwrap().octets()
        );
        None
    }
}
