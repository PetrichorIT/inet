use crate::{
    arp::ArpEntryInternal,
    ctx::IOContext,
    interface::{IfId, Interface, InterfaceAddr},
    ipv6::{addrs::CanidateAddr, timer::TimerToken},
};
use bytepack::{FromBytestream, ToBytestream};
use des::{runtime::sample, time::SimTime};
use inet_types::{
    icmpv6::{
        IcmpV6DestinationUnreachable, IcmpV6DestinationUnreachableCode, IcmpV6Echo,
        IcmpV6MtuOption, IcmpV6NDPOption, IcmpV6NeighborAdvertisment, IcmpV6NeighborSolicitation,
        IcmpV6Packet, IcmpV6PrefixInformation, IcmpV6RouterAdvertisement, IcmpV6RouterSolicitation,
        IcmpV6TimeExceeded, IcmpV6TimeExceededCode, NDP_MAX_RANDOM_FACTOR, NDP_MAX_RA_DELAY_TIME,
        NDP_MIN_RANDOM_FACTOR, NDP_RETRANS_TIMER, PROTO_ICMPV6,
    },
    ip::{IpPacket, Ipv6AddrExt, Ipv6Packet, Ipv6Prefix},
};
use rand::distributions::Uniform;
use std::{
    io,
    net::{IpAddr, Ipv6Addr},
    time::Duration,
};

use super::ndp::QueryType;

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
    // # Neighbor discovery protocol
    //

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

        // FIXME: is this really correct ? or should we just respond with unicast ?

        // let dur_since_last_update = SimTime::now()
        //     .checked_duration_since(self.ipv6.router_state.last_adv_sent)
        //     .unwrap_or(iface_cfg.max_rtr_adv_interval);

        // if dur_since_last_update < iface_cfg.max_rtr_adv_interval {
        //     return Ok(true);
        // }
        // self.ipv6.router_state.last_adv_sent = SimTime::now();

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

        let dst_addr = if ip.src.is_unspecified() {
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

    pub fn ipv6_icmp_send_router_solicitation(&mut self, ifid: IfId) -> io::Result<()> {
        if self.ipv6.is_rooter {
            tracing::warn!("missuse, router shall not request router adv");
            return Ok(());
        }

        let iface = self.get_iface(ifid)?;
        let iface_mac = iface.device.addr;
        let iface_ll = iface
            .link_local_v6()
            .expect("no link local address configured ??");

        tracing::trace!(
            IFACE=%ifid,
            MAC=%iface_mac,
            IP=%iface_ll,
            "requesting router advertisment"
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
            dst: Ipv6Addr::MULTICAST_ALL_ROUTERS,
            content: msg.to_vec()?,
        };

        self.ipv6_send(pkt, ifid)?;
        // TOOD: timeout

        Ok(())
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

                    if Ipv6Prefix::LINK_LOCAL.contains(info.prefix) {
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
                        tracing::debug!(IFACE=%ifid, "assigned new address: {addr}");
                        self.ipv6.prefixes.assign(info, addr)
                    }
                }
                _ => {}
            }
        }

        self.ipv6.neighbors.set_router(ip.src);

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

        // tracing::warn!(IFACE=%ifid, "recv (sol) for {} from {}->{}", req.target, ip.src, ip.dst);

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
                self.ipv6.neighbors.set_reachable(ip.src);
            }
        }

        let dst = if ip.src.is_unspecified() {
            Ipv6Addr::MULTICAST_ALL_NODES
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
            src: Ipv6Addr::UNSPECIFIED,
            dst,
            content: msg.to_vec()?,
        };

        // tracing::warn!(
        //     IFACE=%ifid,
        //     "send (adv) for {} from {}->{}",
        //     req.target,
        //     pkt.src,
        //     pkt.dst
        // );

        self.ipv6_send(pkt, ifid)?;
        Ok(true)
    }

    pub fn ipv6_icmp_send_neighbor_solicitation(
        &mut self,
        target: Ipv6Addr,
        ifid: IfId,
    ) -> io::Result<()> {
        if self
            .ipv6
            .timer
            .active(TimerToken::NeighborSolicitationRetransmitTimeout { target, ifid })
        {
            return Ok(());
        }

        self.ipv6
            .solicitations
            .register(target, QueryType::NeighborSolicitation);

        self.ipv6.neighbors.initalize(target, ifid);

        let iface = self.ifaces.get(&ifid).unwrap();

        // TODO: completetly wrong

        let req = IcmpV6NeighborSolicitation {
            target,
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
            src: Ipv6Addr::UNSPECIFIED,
            dst: Ipv6Addr::solicied_node_multicast(target),
            content: msg.to_vec()?,
        };

        tracing::trace!("send (sol) {} {target}", pkt.src);

        // tracing::trace!(IFACE=%ifid, "send (sol) for {target} from {}->{}", pkt.src, pkt.dst);

        self.ipv6_send(pkt, ifid)?;

        self.ipv6.timer.schedule(
            TimerToken::NeighborSolicitationRetransmitTimeout { target, ifid },
            SimTime::now() + NDP_RETRANS_TIMER,
        );
        self.ipv6.timer.schedule_wakeup();

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

        match query_typ {
            QueryType::NeighborSolicitation => {
                self.ipv6_icmp_neighbor_solicitation_retrans_timeout(target, ifid)
            }
            QueryType::TentativeAddressCheck => {
                self.ipv6_icmp_tentative_solicitaion_retrans_timeout(target, ifid)
            }
        }
    }

    fn ipv6_icmp_neighbor_solicitation_retrans_timeout(
        &mut self,
        target: Ipv6Addr,
        ifid: IfId,
    ) -> io::Result<()> {
        let should_retry = self.ipv6.neighbors.record_timeout(target);
        if should_retry {
            let iface = self.ifaces.get(&ifid).unwrap();

            let req = IcmpV6NeighborSolicitation {
                target,
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
                src: Ipv6Addr::UNSPECIFIED,
                dst: Ipv6Addr::solicied_node_multicast(target),
                content: msg.to_vec()?,
            };

            self.ipv6_send(pkt, ifid)?;

            self.ipv6.timer.schedule(
                TimerToken::NeighborSolicitationRetransmitTimeout { target, ifid },
                SimTime::now() + NDP_RETRANS_TIMER,
            );
            self.ipv6.timer.schedule_wakeup();
            Ok(())
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
        _target: Ipv6Addr,
        _ifid: IfId,
    ) -> io::Result<()> {
        todo!() // Try up to CFG value, then consider addr valid
    }

    pub fn ipv6_icmp_send_unsolicited_adv(&mut self, ifid: IfId, addr: Ipv6Addr) -> io::Result<()> {
        let iface = self.ifaces.get(&ifid).unwrap();

        let adv = IcmpV6NeighborAdvertisment {
            target: addr,
            router: self.ipv6.is_rooter,
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

        // tracing::warn!(IFACE=%ifid, "recv (adv) for {} from {}->{}", adv.target, ip.src, ip.dst);

        let fwd_pkts = self
            .ipv6
            .neighbors
            .process(ifid, &adv, &mut self.ipv6.default_routers);

        self.ipv6.solicitations.remove(adv.target);

        if fwd_pkts {
            for pkt in self.ipv6.neighbors.dequeue(adv.target) {
                self.ipv6_send(pkt, ifid)?;
            }

            self.ipv6
                .timer
                .cancel(TimerToken::NeighborSolicitationRetransmitTimeout {
                    target: adv.target,
                    ifid,
                });
        }

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

        dbg!(&self.addrs);
        dbg!(query, "fe80::abcd".parse::<Ipv6Addr>().unwrap().octets());
        None
    }
}
