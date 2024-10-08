use crate::{
    arp::ArpEntryInternal,
    ctx::IOContext,
    interface::{IfId, InterfaceAddr, InterfaceAddrV6},
    ipv6::{addrs::CanidateAddr, timer::TimerToken, Ipv6SendFlags},
};
use bytepack::{FromBytestream, ToBytestream};
use des::{runtime::sample, time::SimTime};
use types::{
    icmpv6::{
        IcmpV6DestinationUnreachable, IcmpV6DestinationUnreachableCode, IcmpV6Echo,
        IcmpV6MtuOption, IcmpV6NDPOption, IcmpV6NeighborAdvertisment, IcmpV6NeighborSolicitation,
        IcmpV6Packet, IcmpV6PrefixInformation, IcmpV6RouterAdvertisement, IcmpV6RouterSolicitation,
        IcmpV6TimeExceeded, IcmpV6TimeExceededCode, NDP_MAX_RANDOM_FACTOR, NDP_MAX_RA_DELAY_TIME,
        NDP_MAX_RTR_SOLICITATIONS, NDP_MAX_RTR_SOLICITATION_DELAY, NDP_MIN_RANDOM_FACTOR,
        NDP_RETRANS_TIMER, PROTO_ICMPV6,
    },
    ip::{IpPacket, Ipv6AddrExt, Ipv6Packet, Ipv6Prefix},
};
use rand::distributions::Uniform;
use std::{io, net::Ipv6Addr, time::Duration};
use tracing::Level;

use super::{mld, ndp::QueryType};

pub mod ping;
pub mod tracerouter;

impl IOContext {
    pub(crate) fn ipv6_icmp_recv(&mut self, ip: &Ipv6Packet, ifid: IfId) -> io::Result<bool> {
        assert_eq!(ip.next_header, PROTO_ICMPV6);

        let Ok(msg) = IcmpV6Packet::read_from_slice(&mut &ip.content[..]) else {
            tracing::error!(
                "received ip-packet with proto=0x58 (icmpv6) but content was no icmpv6-packet"
            );
            return Ok(false);
        };

        let span = tracing::span!(Level::INFO, "iface", id=%ifid);
        let _guard = span.entered();

        match msg {
            IcmpV6Packet::DestinationUnreachable(msg) => {
                return self.ipv6_icmp_recv_destination_unreachable(ip, msg)
            }
            IcmpV6Packet::TimeExceeded(msg) => return self.ipv6_icmp_recv_time_exceeded(ip, msg),

            IcmpV6Packet::EchoRequest(msg) => {
                let reply = IcmpV6Echo {
                    identifier: msg.identifier,
                    sequence_no: msg.sequence_no,
                    data: msg.data.clone(),
                };
                let msg = IcmpV6Packet::EchoReply(reply);
                let pkt = Ipv6Packet {
                    traffic_class: 0,
                    flow_label: 0,
                    next_header: PROTO_ICMPV6,
                    hop_limit: 64,
                    src: ip.dst,
                    dst: ip.src,
                    content: msg.to_vec()?,
                };
                self.ipv6_send(pkt, ifid)?;
                return Ok(true);
            }
            IcmpV6Packet::EchoReply(msg) => {
                let Some(ping_ctrl) = self.ipv6.ping_ctrl.get_mut(&msg.identifier) else {
                    tracing::warn!(IFACE=%ifid, "received missguided ICMPv6 echo reply id={} seq_no={}", msg.identifier, msg.sequence_no);
                    return Ok(true);
                };
                if let Some(msg) = ping_ctrl.process(msg) {
                    let pkt = Ipv6Packet {
                        traffic_class: 0,
                        flow_label: 0,
                        next_header: PROTO_ICMPV6,
                        hop_limit: 64,
                        src: ip.dst,
                        dst: ip.src,
                        content: msg.to_vec()?,
                    };
                    self.ipv6_send(pkt, ifid)?;
                }
                return Ok(true);
            }

            IcmpV6Packet::MulticastListenerQuery(query) => {
                return self.ipv6_icmp_recv_multicast_listener_query(ip, ifid, query);
            }
            IcmpV6Packet::MulticastListenerReport(report) => {
                return self.ipv6_icmp_recv_multicast_listener_discovery_report(ip, ifid, report);
            }
            IcmpV6Packet::MulticastListenerDone(_) => {}

            IcmpV6Packet::RouterSolicitation(req) => {
                // See RFC 4861 :: 6.1.1
                if ip.hop_limit != 255 {
                    return Ok(true);
                }

                return self.ipv6_icmp_recv_router_solicitation(ip, ifid, req);
            }
            IcmpV6Packet::RouterAdvertisment(adv) => {
                // See RFC 4861 :: 6.1.1
                if ip.hop_limit != 255 {
                    return Ok(true);
                }

                return self.ipv6_icmp_recv_router_advertisment(ip, ifid, adv);
            }
            IcmpV6Packet::NeighborSolicitation(req) => {
                // See RFC 4861 :: 6.1.1
                if ip.hop_limit != 255 {
                    return Ok(true);
                }

                return self.ipv6_icmp_recv_neighbor_solicitation(ip, ifid, req);
            }
            IcmpV6Packet::NeighborAdvertisment(adv) => {
                // See RFC 4861 :: 6.1.1
                if ip.hop_limit != 255 {
                    return Ok(true);
                }

                return self.ipv6_icmp_recv_neighbor_advertisment(ip, ifid, adv);
            }

            _ => tracing::error!(IFACE=%ifid, "unhandled ICMP message {msg:?}"),
        }

        Ok(true)
    }

    fn ipv6_icmp_recv_destination_unreachable(
        &mut self,
        _ip: &Ipv6Packet,
        msg: IcmpV6DestinationUnreachable,
    ) -> io::Result<bool> {
        let original = Ipv6Packet::read_from_slice(&mut &msg.packet[..])?;
        let dst = original.dst;

        // (0) Check active ICMP handlers
        self.ipv6.ping_ctrl.retain(|_, ping| {
            if ping.addr == dst {
                ping.fail_with_error(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    format!("destination unreachable: {:?}", msg.code),
                ));
                false
            } else {
                true
            }
        });

        // (1) Check for sockets
        for (fd, socket) in self
            .sockets
            .iter()
            .filter(|(_, socket)| socket.peer.ip() == dst)
            .map(|(fd, sock)| (*fd, (sock.domain, sock.typ)))
            .collect::<Vec<_>>()
        {
            use crate::socket::SocketDomain::*;
            use crate::socket::SocketType::*;

            match socket {
                (AF_INET6, SOCK_DGRAM) => self.udp_icmp_error(
                    fd,
                    io::Error::new(
                        io::ErrorKind::ConnectionRefused,
                        format!("destination unreachable: {:?}", msg.code),
                    ),
                    IpPacket::V6(original.clone()),
                ),
                (AF_INET6, SOCK_STREAM) => self.tcp_icmp_destination_unreachable(
                    fd,
                    io::Error::new(
                        io::ErrorKind::ConnectionRefused,
                        format!("destination unreachable: {:?}", msg.code),
                    ),
                ),
                _ => todo!(),
            }
        }

        Ok(true)
    }

    fn ipv6_icmp_recv_time_exceeded(
        &mut self,
        _ip: &Ipv6Packet,
        msg: IcmpV6TimeExceeded,
    ) -> io::Result<bool> {
        let original = Ipv6Packet::read_from_slice(&mut &msg.packet[..])?;
        let dst = original.dst;

        // (0) Check active ICMP handlers
        self.ipv6.ping_ctrl.retain(|_, ping| {
            if ping.addr == dst {
                ping.fail_with_error(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    format!("time exceeded: {:?}", msg.code),
                ));
                false
            } else {
                true
            }
        });

        // (1) Check for sockets
        for (fd, socket) in self
            .sockets
            .iter()
            .filter(|(_, socket)| socket.peer.ip() == dst)
            .map(|(fd, sock)| (*fd, (sock.domain, sock.typ)))
            .collect::<Vec<_>>()
        {
            use crate::socket::SocketDomain::*;
            use crate::socket::SocketType::*;

            match socket {
                (AF_INET6, SOCK_DGRAM) => self.udp_icmp_error(
                    fd,
                    io::Error::new(
                        io::ErrorKind::ConnectionRefused,
                        format!("time exceeded: {:?}", msg.code),
                    ),
                    IpPacket::V6(original.clone()),
                ),
                (AF_INET6, SOCK_STREAM) => self.tcp_icmp_destination_unreachable(
                    fd,
                    io::Error::new(
                        io::ErrorKind::ConnectionRefused,
                        format!("time exceeded: {:?}", msg.code),
                    ),
                ),
                _ => todo!(),
            }
        }

        Ok(true)
    }

    pub fn ipv6_icmp_send_ttl_expired(&mut self, pkt: &Ipv6Packet, ifid: IfId) -> io::Result<()> {
        // TODO: prevent loops

        let err = IcmpV6TimeExceeded {
            code: IcmpV6TimeExceededCode::HopLimitExceeded,
            packet: pkt.to_vec()?,
        };
        let msg = IcmpV6Packet::TimeExceeded(err);
        let pkt = Ipv6Packet {
            traffic_class: 0,
            flow_label: 0,
            next_header: PROTO_ICMPV6,
            hop_limit: 32,
            src: Ipv6Addr::UNSPECIFIED,
            dst: pkt.src,
            content: msg.to_vec()?,
        };
        self.ipv6_send(pkt, ifid)?;
        Ok(())
    }

    //
    // # MLD
    //

    //
    // # Neighbor discovery protocol
    //

    fn ipv6_icmp_recv_router_solicitation(
        &mut self,
        ip: &Ipv6Packet,
        ifid: IfId,
        req: IcmpV6RouterSolicitation,
    ) -> io::Result<bool> {
        // See RFC 4861 :: 6.1.1
        if !self.ipv6.is_router {
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

        let iface_cfg = self.ipv6.router_cfg.get(&ifid).unwrap();

        let dst = if ip.src.is_unspecified() {
            Ipv6Addr::MULTICAST_ALL_NODES
        } else {
            // RFC 4861 defines that we are allowed to just
            // use the multicast address either way
            if iface_cfg.allow_solicited_advertisments_unicast {
                ip.src
            } else {
                Ipv6Addr::MULTICAST_ALL_NODES
            }
        };

        // TODO:
        // Delay advertisment response, only send singe adv to multiple solicitations
        let delay_time = SimTime::now()
            + Duration::from_secs_f64(sample(Uniform::new(
                0.0,
                NDP_MAX_RA_DELAY_TIME.as_secs_f64(),
            )));

        // TODO:
        // Rate limit sendings to MULTICAST:ALLNODES according to NDP_MIN_DELAY_BETWEEN_RAS

        let token = TimerToken::RouterAdvertismentSolicited { ifid, dst };

        if self.ipv6.timer.active(&token).is_none() {
            self.ipv6.timer.schedule(token, delay_time);
        }

        Ok(true)
    }

    pub fn ipv6_icmp_send_router_adv(&mut self, ifid: IfId, dst: Ipv6Addr) -> io::Result<()> {
        let iface = self.ifaces.get(&ifid).unwrap();
        let iface_mac = iface.device.addr;
        let iface_cfg = self.ipv6.router_cfg.get(&ifid).unwrap();
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
                            prefix_len: entry.prefix.len(),
                            prefix: entry.prefix.addr(),
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

        let msg = IcmpV6Packet::RouterAdvertisment(adv);
        let pkt = Ipv6Packet {
            traffic_class: 0,
            flow_label: 0,
            next_header: PROTO_ICMPV6,
            hop_limit: 255,
            src: Ipv6Addr::UNSPECIFIED,
            dst,
            content: msg.to_vec()?,
        };

        self.ipv6_send(pkt, ifid)?;
        Ok(())
    }

    pub fn ipv6_icmp_send_router_solicitation(&mut self, ifid: IfId) -> io::Result<()> {
        if self.ipv6.is_router {
            tracing::warn!("missuse, router shall not request router adv");
            return Ok(());
        }

        let iface = self.get_iface(ifid)?;
        let iface_mac = iface.device.addr;

        tracing::trace!(
            IFACE=%ifid,
            MAC=%iface_mac,
            "requesting router advertisment"
        );

        // Check whether iface has availabe addr
        let set = self.ipv6_src_addr_canidate_set(Ipv6Addr::MULTICAST_ALL_ROUTERS, ifid);
        let src = set
            .select(&self.ipv6.policies)
            .map(|canidate| canidate.addr);

        // Send inital router solictation
        let req = IcmpV6RouterSolicitation {
            options: if src.is_some() {
                vec![IcmpV6NDPOption::SourceLinkLayerAddress(iface_mac)]
            } else {
                Vec::new()
            },
        };
        let msg = IcmpV6Packet::RouterSolicitation(req);
        let pkt = Ipv6Packet {
            traffic_class: 0,
            flow_label: 0,
            next_header: PROTO_ICMPV6,
            hop_limit: 255,
            src: src.unwrap_or(Ipv6Addr::UNSPECIFIED),
            dst: Ipv6Addr::MULTICAST_ALL_ROUTERS,
            content: msg.to_vec()?,
        };

        self.ipv6_send_with_flags(pkt, ifid, Ipv6SendFlags::ALLOW_SRC_UNSPECIFIED)?;
        // TOOD: timeout

        Ok(())
    }

    fn ipv6_icmp_recv_router_advertisment(
        &mut self,
        ip: &Ipv6Packet,
        ifid: IfId,
        adv: IcmpV6RouterAdvertisement,
    ) -> io::Result<bool> {
        if self.ipv6.is_router {
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

        let mut new_bindings = Vec::new();

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

                    if Ipv6Prefix::LINK_LOCAL.contains(info.prefix) {
                        // link local is silently ignored
                        continue;
                    }

                    let autocfg = self.ipv6.prefixes.update(&info);
                    if autocfg {
                        let iface = self.ifaces.get(&ifid).unwrap();
                        let addr = iface.device.addr.embed_into(info.prefix);

                        let mut binding =
                            InterfaceAddrV6::new_static(addr, info.prefix_len as usize);
                        let validity = Duration::from_millis(info.preferred_lifetime as u64);
                        binding.deadline = SimTime::now() + validity;
                        binding.validity = validity;

                        new_bindings.push((ifid, binding, info));
                    } else {
                        // TODO: reset prefix timeout
                        if let Some(timeout) = self.ipv6.prefixes.timeout_for(&info) {
                            self.ipv6.timer.reschedule(
                                &TimerToken::PrefixTimeout {
                                    ifid,
                                    prefix: info.prefix(),
                                },
                                timeout,
                            );
                        }
                    }
                }
                _ => {}
            }
        }

        self.ipv6.neighbors.set_router(ip.src);

        for (ifid, binding, info) in new_bindings {
            let addr = binding.addr;
            self.interface_add_addr_v6(ifid, binding, false)?;
            self.ipv6.prefixes.assign(info, addr); // TODO: not sure if before or after address assigning
            if let Some(timeout) = self.ipv6.prefixes.timeout_for(&info) {
                self.ipv6.timer.schedule(
                    TimerToken::PrefixTimeout {
                        ifid,
                        prefix: info.prefix(),
                    },
                    timeout,
                );
            }
        }

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
            if let Some(unicast_addr) = iface.addrs.v6.addrs().next() {
                if unicast_addr != ip.dst {
                    return Ok(true);
                }

                if src_mac_entry.is_some() {
                    return Ok(true);
                }
            }
        }

        let query_is_dedup = ip.src.is_unspecified();
        let tentative = !iface.addrs.v6.matches(req.target);

        tracing::trace!(IFACE=%ifid, tentative, "recv (sol) for {} from {}->{}", req.target, ip.src, ip.dst);

        if tentative {
            // Do not response, if the address id tentative

            // TODO: check whether src of sol is self, then ignore
            if query_is_dedup {
                // Check whether this query asks for the same address as an active dedup assigment
                let Some(query) = self.ipv6.solicitations.lookup(req.target) else {
                    return Ok(true);
                };

                let QueryType::TentativeAddressCheck(binding) = query else {
                    return Ok(true);
                };

                self.ipv6_icmp_tentative_addr_check_failed(ifid, binding)?;
                return Ok(true);
            }

            return Ok(true);
        }

        let iface_mac = iface.device.addr;

        if !ip.src.is_unspecified() {
            if let Some(mac) = src_mac_entry {
                self.ipv6.neighbors.update(ip.src, *mac, ifid, false);

                // TODO:
                // This Implementation is not correct:
                // - state should be STALE and no packets should be send until reachabel
                // - for now this is fine

                self.ipv6.neighbors.set_reachable(ip.src);
                let pkts = self.ipv6.neighbors.dequeue(ip.src);
                for pkt in pkts {
                    self.ipv6_send(pkt, ifid)?;
                }
            }
        }

        let dst = if ip.src.is_unspecified() {
            Ipv6Addr::MULTICAST_ALL_NODES
        } else {
            ip.src
        };

        let adv = IcmpV6NeighborAdvertisment {
            target: req.target,
            router: self.ipv6.is_router,
            solicited: !ip.src.is_unspecified(),
            overide: false,
            options: vec![IcmpV6NDPOption::TargetLinkLayerAddress(iface_mac)],
        };
        let msg = IcmpV6Packet::NeighborAdvertisment(adv);
        let pkt = Ipv6Packet {
            traffic_class: 0,
            flow_label: 0,
            next_header: PROTO_ICMPV6,
            hop_limit: 255,
            src: Ipv6Addr::UNSPECIFIED,
            dst,
            content: msg.to_vec()?,
        };

        self.ipv6_send(pkt, ifid)?;
        Ok(true)
    }

    pub fn ipv6_icmp_send_neighbor_solicitation(
        &mut self,
        target: Ipv6Addr,
        ifid: IfId,
        query: QueryType,
    ) -> io::Result<()> {
        // If there is a currently active query, shortciruit
        // -> active means sol send, but no response just yet
        //    still within the timeout limit
        if let Some(_active_sol) = self.ipv6.solicitations.lookup(target) {
            return Ok(());
        }

        // Solisitations must be limited to one interface.
        let Some(iface) = self.ifaces.get_mut(&ifid) else {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "no interface found for ifid",
            ));
        };

        // Reponses to Solicitations may be sen on the ALL_NODES multicast
        // so joining this multicast is of the utmost importance
        iface.addrs.v6.join(Ipv6Addr::MULTICAST_ALL_NODES);

        // Solicitations may be casued by either an send:address_resolution or
        // the assigment of a local address (tentaive address check). Different cases
        // may require different procedures.
        let is_dedup = matches!(query, QueryType::TentativeAddressCheck(_));
        if is_dedup {
            let first_pkt_after_reinit = iface.send_q == 0;
            if first_pkt_after_reinit {
                // If this interface is new, delay the multicast join for the sol multicast
                // to prevent loops.
                let delay = Duration::from_secs_f64(
                    NDP_MAX_RTR_SOLICITATION_DELAY.as_secs_f64()
                        * des::runtime::random::<f64>()
                        * 0.0,
                    // TODO: RFC 4862 specifies that:
                    // - a node should delay joining the sol node multicast of tentative addrs
                    // - within the delay, ICMP messages to all-node or sol-node should still be handled
                    //
                    // This requires some mechanism to accept MACs of sol-node-mc, but still not join the multicast group ???
                );
                self.ipv6.timer.schedule(
                    TimerToken::DelayedJoinMulticast {
                        ifid,
                        multicast: Ipv6Addr::solicied_node_multicast(target),
                    },
                    SimTime::now() + delay,
                );
            } else {
                // Else join immediatly and ping MLD
                let multicast = Ipv6Addr::solicied_node_multicast(target);

                let needs_mld_report = iface.addrs.v6.join(multicast);
                if needs_mld_report {
                    self.mld_on_event(ifid, mld::Event::StartListening, multicast)?;
                }
            }
        }

        // Query in progess: register as such based on the target.
        self.ipv6.solicitations.register(target, query);

        // No Timer for the current query should exist, because else the query
        // would be registerd in ipv6.solicitations thus this function would have shortciruited.
        if self
            .ipv6
            .timer
            .active(&TimerToken::NeighborSolicitationRetransmitTimeout { target, ifid })
            .is_some()
        {
            unreachable!("any sol should be saved in ipv6.solicitations, but non was found")
        }

        // Initalize structs and send solicitation
        self.ipv6.neighbors.initalize(target, ifid);
        self.ipv6_icmp_send_neighbor_solicitation_raw(target, ifid, is_dedup)
    }

    fn ipv6_icmp_send_neighbor_solicitation_raw(
        &mut self,
        target: Ipv6Addr,
        ifid: IfId,
        is_dedup: bool,
    ) -> io::Result<()> {
        let iface_addr = self.ifaces.get(&ifid).unwrap().device.addr;

        let dst = Ipv6Addr::solicied_node_multicast(target);
        let set = self.ipv6_src_addr_canidate_set(dst, ifid);
        let src = set
            .select(&self.ipv6.policies)
            .map(|canidate| canidate.addr);

        let req = IcmpV6NeighborSolicitation {
            target,
            options: if src.is_some() {
                vec![IcmpV6NDPOption::SourceLinkLayerAddress(iface_addr)]
            } else {
                Vec::new()
            },
        };
        let msg = IcmpV6Packet::NeighborSolicitation(req);
        let pkt = Ipv6Packet {
            traffic_class: 0,
            flow_label: 0,
            next_header: PROTO_ICMPV6,
            hop_limit: 255,
            src: src.unwrap_or(Ipv6Addr::UNSPECIFIED),
            dst,
            content: msg.to_vec()?,
        };

        tracing::trace!("send (sol) from {} for {target}", pkt.src);

        // tracing::trace!(IFACE=%ifid, "send (sol) for {target} from {}->{}", pkt.src, pkt.dst);

        let mut flags = Ipv6SendFlags::ALLOW_SRC_UNSPECIFIED;
        if is_dedup {
            flags |= Ipv6SendFlags::REQUIRED_SRC_UNSPECIFIED;
        }
        self.ipv6_send_with_flags(pkt, ifid, flags)?;

        self.ipv6.timer.schedule(
            TimerToken::NeighborSolicitationRetransmitTimeout { target, ifid },
            SimTime::now() + NDP_RETRANS_TIMER,
        );

        Ok(())
    }

    pub fn ipv6_icmp_solicitation_retrans_timeout(
        &mut self,
        target: Ipv6Addr,
        ifid: IfId,
    ) -> io::Result<()> {
        let Some(query_typ) = self.ipv6.solicitations.lookup(target) else {
            tracing::error!("timeout referring to unknown query {target} @{ifid}");
            return Ok(());
        };

        let _guard = tracing::span!(Level::INFO, "iface", id=%ifid).entered();

        match query_typ {
            QueryType::NeighborSolicitation => {
                self.ipv6_icmp_neighbor_solicitation_retrans_timeout(target, ifid)
            }
            QueryType::TentativeAddressCheck(binding) => {
                self.ipv6_icmp_tentative_solicitaion_retrans_timeout(ifid, binding)
            }
        }
    }

    fn ipv6_icmp_neighbor_solicitation_retrans_timeout(
        &mut self,
        target: Ipv6Addr,
        ifid: IfId,
    ) -> io::Result<()> {
        let should_retry = self
            .ipv6
            .neighbors
            .record_timeout(target)
            .unwrap_or(usize::MAX)
            <= NDP_MAX_RTR_SOLICITATIONS;
        if should_retry {
            self.ipv6_icmp_send_neighbor_solicitation_raw(target, ifid, false)
        } else {
            tracing::warn!(IFACE=%ifid, "could no resolve address for {target}");

            // TODO:
            // Make routing capable
            // ICMP errors may not only be emitted to the current node, but previous nodes on the path

            let set = self.ipv6_src_addr_canidate_set(target, ifid);
            let addr = set
                .select(&self.ipv6.policies)
                .unwrap_or(CanidateAddr::UNSPECIFED);

            let queue = self.ipv6.neighbors.dequeue(target);
            for pkt in queue {
                let error_msg = IcmpV6DestinationUnreachable {
                    code: IcmpV6DestinationUnreachableCode::AddressUnreachable,
                    packet: pkt.to_vec()?,
                };
                let msg = IcmpV6Packet::DestinationUnreachable(error_msg);
                let ip = Ipv6Packet {
                    traffic_class: 0,
                    flow_label: 0,
                    next_header: PROTO_ICMPV6,
                    hop_limit: 0,
                    src: *addr,
                    dst: *addr,
                    content: msg.to_vec()?,
                };

                self.ipv6_send(ip, ifid)?;
            }

            Ok(())
        }
    }

    fn ipv6_icmp_tentative_solicitaion_retrans_timeout(
        &mut self,
        ifid: IfId,
        mut binding: InterfaceAddrV6,
    ) -> io::Result<()> {
        let number_of_sol = self.ipv6.neighbors.record_timeout(binding.addr).unwrap();
        let should_retry = number_of_sol <= self.ipv6.cfg.dup_addr_detect_transmits;

        if should_retry {
            self.ipv6_icmp_send_neighbor_solicitation_raw(binding.addr, ifid, true)
        } else {
            self.ipv6.neighbors.remove(binding.addr);
            self.ipv6.solicitations.remove(binding.addr);
            tracing::debug!(addr=%binding.addr, "deduplication succeeded");

            let Some(iface) = self.ifaces.get_mut(&ifid) else {
                todo!()
            };

            if binding.validity != Duration::MAX {
                binding.deadline = SimTime::now() + binding.validity;
            }
            iface.addrs.add(InterfaceAddr::Inet6(binding));
            Ok(())
        }
    }

    #[allow(unused)]
    pub fn ipv6_icmp_send_unsolicited_adv(&mut self, ifid: IfId, addr: Ipv6Addr) -> io::Result<()> {
        let iface = self.ifaces.get(&ifid).unwrap();

        let adv = IcmpV6NeighborAdvertisment {
            target: addr,
            router: self.ipv6.is_router,
            solicited: false,
            overide: true,
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
            src: addr,
            dst: Ipv6Addr::MULTICAST_ALL_NODES,
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

        let Some(query) = self.ipv6.solicitations.lookup(adv.target) else {
            tracing::warn!("unknown query received.");
            return Ok(true);
        };

        tracing::trace!(IFACE=%ifid, "recv (adv) for {} from {}->{} on {:?}", adv.target, ip.src, ip.dst, query);

        if let QueryType::TentativeAddressCheck(binding) = query {
            self.ipv6_icmp_tentative_addr_check_failed(ifid, binding)?;
            return Ok(true);
        }

        let fwd_pkts = self
            .ipv6
            .neighbors
            .process(ifid, &adv, &mut self.ipv6.default_routers);

        self.ipv6.solicitations.remove(adv.target);

        if fwd_pkts {
            for pkt in self.ipv6.neighbors.dequeue(adv.target) {
                self.ipv6_send(pkt, ifid)?;
            }
        }

        // Reset timer independe of FWD responses
        self.ipv6
            .timer
            .cancel(&TimerToken::NeighborSolicitationRetransmitTimeout {
                target: adv.target,
                ifid,
            });

        // TODO: router changes may need to be propagated

        Ok(true)
    }

    fn ipv6_icmp_tentative_addr_check_failed(
        &mut self,
        ifid: IfId,
        binding: InterfaceAddrV6,
    ) -> io::Result<()> {
        tracing::error!(IFACE=%ifid, "address dedup failed for '{binding}'");
        self.ipv6.solicitations.remove(binding.addr);
        self.ipv6
            .timer
            .cancel(&TimerToken::NeighborSolicitationRetransmitTimeout {
                target: binding.addr,
                ifid,
            });

        let Some(iface) = self.ifaces.get_mut(&ifid) else {
            todo!();
        };

        iface
            .addrs
            .v6
            .leave(Ipv6Addr::solicied_node_multicast(binding.addr));

        Ok(())
    }
}
