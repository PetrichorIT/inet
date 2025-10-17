use std::{
    io::{self, Error, ErrorKind},
    net::Ipv6Addr,
    time::Duration,
};

use bitflags::bitflags;
use des::net::message::{Message, schedule_in};
use fxhash::{FxBuildHasher, FxHashMap};
use multicast::{GroupEvent, MulticastListenerDiscoveryCtrl, NodeEvent, RouterEvent};
use tracing::Level;
use types::{
    icmpv6::PROTO_ICMPV6,
    iface::MacAddress,
    ip::{IpPacket, Ipv6AddrExt, Ipv6Packet, Ipv6Prefix, KIND_IPV6},
};

use crate::{
    ctx::{IOContext, NetworkLayerResult},
    interface::{IfId, IfSpec, InterfaceError},
    ipv6::addrs::CanidateAddr,
};

use self::{
    addrs::PolicyTable,
    cfg::{HostConfiguration, RouterInterfaceConfiguration},
    icmp::{ping::PingCtrl, tracerouter::TracerouteCB},
    ndp::{
        DefaultRouterList, DestinationCache, NeighborCache, PrefixList, QueryType, Solicitations,
    },
    path::PathMtuStore,
    router::{Router, RouterState},
    state::InterfaceState,
    timer::TimerCtrl,
};

pub mod addrs;
pub mod api;
pub mod cfg;
pub mod icmp;
pub mod multicast;
pub mod ndp;
pub mod path;
pub mod router;
pub mod state;
pub mod timer;
pub mod util;

pub struct Ipv6 {
    pub timer: TimerCtrl,

    // Unicast addr mappings
    pub solicitations: Solicitations,
    pub neighbors: NeighborCache,
    pub destinations: DestinationCache,
    pub prefixes: PrefixList,
    pub default_routers: DefaultRouterList,

    pub path_mtu: PathMtuStore,

    // Multicast management
    pub iface_state: FxHashMap<IfId, InterfaceState>,
    pub mld: FxHashMap<IfId, MulticastListenerDiscoveryCtrl>,

    pub is_router: bool,
    pub router: Router,
    pub cfg: HostConfiguration,
    pub router_cfg: FxHashMap<IfId, RouterInterfaceConfiguration>,
    pub router_cfg_default: Option<RouterInterfaceConfiguration>,
    pub router_state: RouterState,

    pub policies: PolicyTable,

    // ICMP utils
    pub ping_ctrl: FxHashMap<u16, PingCtrl>,
    pub traceroute_ctrl: FxHashMap<Ipv6Addr, TracerouteCB>,
}

impl Ipv6 {
    pub fn new() -> Self {
        Ipv6 {
            timer: TimerCtrl::new(),

            solicitations: Solicitations::new(),
            neighbors: NeighborCache::default(),
            destinations: DestinationCache::default(),
            prefixes: PrefixList::new(),
            default_routers: DefaultRouterList::new(),

            path_mtu: PathMtuStore::default(),

            iface_state: FxHashMap::with_hasher(FxBuildHasher::default()),
            mld: FxHashMap::with_hasher(FxBuildHasher::default()),

            cfg: HostConfiguration::default(),
            is_router: false,
            router: Router::new(),
            router_cfg: FxHashMap::with_hasher(FxBuildHasher::default()),
            router_cfg_default: None,
            router_state: RouterState::new(),

            policies: PolicyTable::default(),

            ping_ctrl: FxHashMap::with_hasher(FxBuildHasher::default()),
            traceroute_ctrl: FxHashMap::with_hasher(FxBuildHasher::default()),
        }
    }
}

impl Default for Ipv6 {
    fn default() -> Self {
        Self::new()
    }
}

bitflags! {
    #[derive(Debug)]
    pub struct Ipv6SendFlags: u8 {
        const DEFAULT = 0b0000_0000;
        const ALLOW_SRC_UNSPECIFIED = 0b0000_0001;
        const REQUIRED_SRC_UNSPECIFIED = 0b0000_0010;
        const FOREIGN_PACKET = 0b0000_0100;
    }
}

impl IOContext {
    pub fn ipv6_recv(&mut self, msg: Message, ifid: IfId) -> NetworkLayerResult {
        let Ok((pkt, header, _)) = msg.try_into_content::<Ipv6Packet>() else {
            tracing::error!(
                "received eth-packet with kind=0x86DD (ip) but content was no ipv6-packet"
            );
            return NetworkLayerResult::Consumed();
        };

        let iface = self
            .ifaces
            .get(&ifid)
            .expect("interface was already resolved");

        let is_local_dest = iface.bindings.v6.matches_recv(pkt.dst) || pkt.dst.is_multicast();
        if !is_local_dest {
            let mut pkt = pkt;

            if pkt.hop_limit == 0 {
                tracing::warn!("dropped ipv6-packet with ttl 0");
                self.ipv6_icmp_send_ttl_expired(&pkt, ifid)
                    .expect("ttl expired failed");
                return NetworkLayerResult::Consumed();
            }
            pkt.hop_limit = pkt.hop_limit.saturating_sub(1);

            if let Err(error) = self.ipv6_send_with_flags(
                pkt, // TODO: to not copy, use a result Err(Packet)
                None,
                Ipv6SendFlags::FOREIGN_PACKET,
            ) {
                tracing::error!("failed to forward ip-packet {error}");
                panic!("TODO: cannot send ipv6 packet")
            }

            return NetworkLayerResult::Consumed();
        }

        match pkt.proto {
            PROTO_ICMPV6 => {
                let _consumed = self.ipv6_icmp_recv(&pkt, ifid);
                NetworkLayerResult::Consumed()
            }
            0 => NetworkLayerResult::PassThrough(Message::from_parts(header, Some(pkt))),
            _ => NetworkLayerResult::TransportLayerPacket(IpPacket::V6(pkt), header),
        }
    }
}

impl IOContext {
    pub fn ipv6_send(&mut self, pkt: Ipv6Packet, ifid: IfSpec) -> io::Result<()> {
        self.ipv6_send_with_flags(pkt, ifid, Ipv6SendFlags::DEFAULT)
    }

    pub fn ipv6_send_with_flags(
        &mut self,
        pkt: Ipv6Packet,
        ifid: IfSpec,
        flags: Ipv6SendFlags,
    ) -> io::Result<()> {
        // tracing::trace!(src = ?pkt.src, dst = ?pkt.dst, ?ifid, "ipv6_send({flags:?})");

        // Check that dst is not unspecified, this should have been handled allready
        if pkt.dst.is_unspecified() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "packet without destination found",
            ));
        }

        if pkt.dst.is_multicast() {
            if ifid.is_none() {
                self.ipv6_send_multicast(pkt, flags)
            } else {
                // Since no duplication is required, treat the packet as unicast
                self.ipv6_send_unicast(pkt, ifid, flags)
            }
        } else {
            self.ipv6_send_unicast(pkt, ifid, flags)
        }
    }

    /// Send a valid IPv6 packet with a given unicast destination
    /// - pkt.dst must be a valid unicast addr
    /// - ifid may be IfId::NULL but never IfId::ALL
    fn ipv6_send_unicast(
        &mut self,
        mut pkt: Ipv6Packet,
        mut ifspec: IfSpec,
        flags: Ipv6SendFlags,
    ) -> io::Result<()> {
        debug_assert!(!pkt.dst.is_unspecified());

        // (1)
        if pkt.src.is_unspecified() && !flags.contains(Ipv6SendFlags::REQUIRED_SRC_UNSPECIFIED) {
            let canidates = self.ipv6_src_addr_canidate_set(pkt.dst, ifspec);
            if let Some(src) = canidates.select(&self.ipv6.policies) {
                pkt.src = src.addr;
                if ifspec.is_none() {
                    ifspec = src.ifid.into();
                }
            } else if flags.contains(Ipv6SendFlags::ALLOW_SRC_UNSPECIFIED) {
                /* Do nothing the flag allows this */
            } else {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    "host unreachable - no valid src addr",
                ));
            }
        }

        // `ifid` may be NULL, `pkt.src` is set expect ALLOW_SRC_UNSPECIFIED

        // (2) Self-Send bypass
        if pkt.src == pkt.dst {
            debug_assert!(!pkt.src.is_unspecified());

            // TODO: this is not correct
            let loopback = self.ifaces.values_mut().find(|iface| iface.flags.loopback);
            if let Some(loopback) = loopback {
                loopback
                    .send_buffered(Message::default().with_kind(KIND_IPV6).with_content(pkt))?;
            } else {
                assert!(ifspec.is_some());
                // FIXME: dangerous since this execut4e directly
                let iface = self.ifaces.get(&ifspec.unwrap()).unwrap();
                schedule_in(
                    Message::default()
                        .with_last_gate(iface.device.input().unwrap())
                        .with_kind(KIND_IPV6)
                        .with_src(iface.device.addr.into())
                        .with_dst(iface.device.addr.into())
                        .with_content(pkt),
                    Duration::ZERO,
                );
            }

            return Ok(());
        }

        // (3) if the packet is foreign no IfId could be provided by (1) since the
        // src addr is already fixed, thus compute a valid IfId for by input
        if ifspec.is_none() && !flags.contains(Ipv6SendFlags::FOREIGN_PACKET) {
            ifspec = self.ipv6_ifid_for_src_addr(pkt.src).into();
        }

        // (4) Next hop determination (routing)
        // Figure out the appropriate next hop if that is not cached. If it is
        // ifid will also be cached so no need to set
        let next_hop = self.ipv6.destinations.lookup(pkt.dst, &self.ipv6.neighbors);
        let next_hop = if let Some(next_hop) = next_hop {
            next_hop
        } else {
            let (next_hop, new_ifid) = self.ipv6_next_hop_determination(pkt.src, pkt.dst)?;
            if new_ifid.is_some() {
                ifspec = new_ifid;
            }
            next_hop
        };

        // `ifid` may be NULL
        // `next_hop` is an adjacent node

        // (5) Link layer resolution
        let Some((mac_addr, lookup_ifid)) = self.ipv6.neighbors.lookup(next_hop) else {
            // we cannot find a LL address for a node that should be adjacent
            // -> node does not exist OR not yet resolved
            // -> LL resolution must be started (requires interface)
            // -> `IfId` may be NULL if [not provided by the socket && not set by src specification && not foreign packet]
            // -> `next_hop` must be assumed on link -> thus determine where
            let ifid = if let Some(ifid) = ifspec {
                ifid
            } else {
                debug_assert!(self.ipv6.is_router);
                // We still dont know where to look -> router?
                for (cifid, ccfg) in &self.ipv6.router_cfg {
                    if ccfg
                        .adv_prefix_list
                        .iter()
                        .any(|pr| pr.prefix.contains(next_hop))
                    {
                        ifspec = (*cifid).into();
                    }
                }
                ifspec.expect("could not assign any interface")
            };

            // Link-Layer resolution is not directly available
            // -> start solicitation procedure and queue packet
            self.ipv6_icmp_send_neighbor_solicitation(
                next_hop,
                ifid,
                QueryType::NeighborSolicitation,
            )?;
            self.ipv6.neighbors.enqueue(next_hop, pkt);
            return Ok(());
        };

        if lookup_ifid.is_some() {
            ifspec = lookup_ifid;
        };

        let ifid = ifspec.expect("illegal state");

        // (6) Message assembly
        let iface = self.ifaces.get_mut(&ifid).expect("illegal state");
        let msg = Message::default()
            .with_src(iface.device.addr.into())
            .with_dst(mac_addr.into())
            .with_kind(KIND_IPV6)
            .with_content(pkt);

        // (7) Send packet
        if let Err(err) = iface.send_buffered(msg) {
            match err {
                InterfaceError::PacketToBig(pkt, allowed_mtu) => {
                    // If packet is non-local send a ICMP packet to big message
                    if flags.contains(Ipv6SendFlags::FOREIGN_PACKET) {
                        self.ipv6_icmp_send_packet_to_big(
                            pkt.body.content::<Ipv6Packet>(),
                            allowed_mtu,
                        )?;
                    } else {
                        tracing::error!("locally send packet exceeds local max MTU");
                        return Err(Error::new(
                            ErrorKind::InvalidInput,
                            "packet exceeds local max MTU",
                        ));
                    }
                }
            }
        }

        Ok(())
    }

    fn ipv6_send_multicast(&mut self, pkt: Ipv6Packet, _flags: Ipv6SendFlags) -> Result<(), Error> {
        let ifids = self
            .ifaces
            .values()
            .filter_map(|iface| iface.bindings.has_v6_capability().then_some(iface.id()))
            .collect::<Vec<_>>();

        for ifid in ifids {
            let mut pkt = pkt.clone();
            if pkt.src.is_unspecified() {
                let canidates = self.ipv6_src_addr_canidate_set(pkt.dst, Some(ifid));
                if let Some(src) = canidates.select(&self.ipv6.policies) {
                    pkt.src = src.addr;
                } else {
                    continue;
                }
            }

            let mac = MacAddress::ipv6_multicast(pkt.dst);
            let iface = self.ifaces.get_mut(&ifid).unwrap();
            let msg = Message::default()
                .with_src(iface.device.addr.into())
                .with_dst(mac.into())
                .with_kind(KIND_IPV6)
                .with_content(pkt);

            if let Err(err) = iface.send_buffered(msg) {
                match err {
                    InterfaceError::PacketToBig(_, _) => {
                        // If packet is non-local send a ICMP packet to big message

                        tracing::error!("locally send multicast packet exceeds local max MTU");
                        return Err(Error::new(
                            ErrorKind::InvalidInput,
                            "packet exceeds local max MTU",
                        ));
                    }
                }
            }
        }

        Ok(())
    }

    pub fn ipv6_determine_iface_for_write_interest(
        &mut self,
        src: Ipv6Addr,
        dst: Ipv6Addr,
    ) -> io::Result<IfId> {
        debug_assert!(!dst.is_unspecified());
        debug_assert!(!dst.is_multicast()); // Multicast could be send onto any iface

        if src.is_unspecified() {
            self.ipv6_src_addr_for_dst(dst, None)
                .map(|canid| canid.ifid)
                .ok_or_else(|| Error::new(ErrorKind::NotFound, "no capable src addr"))
        } else {
            // (2) `src` is set to a given unicast addr -> must be on any interface
            Ok(self.ipv6_ifid_for_src_addr(src))
        }
    }
    pub fn ipv6_src_addr_for_dst(&self, dst: Ipv6Addr, ifspec: IfSpec) -> Option<CanidateAddr> {
        let canidates = self.ipv6_src_addr_canidate_set(dst, ifspec);
        canidates.select(&self.ipv6.policies)
    }

    fn ipv6_ifid_for_src_addr(&self, src: Ipv6Addr) -> IfId {
        for iface in self.ifaces.values() {
            if iface.bindings.v6.matches_recv(src) {
                return iface.id();
            }
        }

        panic!("Could not specifed src interface for addr {src}")
    }

    fn ipv6_next_hop_determination(
        &mut self,
        src: Ipv6Addr,
        dst: Ipv6Addr,
    ) -> io::Result<(Ipv6Addr, IfSpec)> {
        if let Some(next_hop) = self.ipv6.prefixes.next_hop_determination(dst) {
            tracing::trace!("cached next hop {next_hop} for destination {dst}");
            self.ipv6.destinations.set(dst, next_hop);
            Ok((next_hop, None))
        } else {
            if self.ipv6.is_router {
                if let Some(v) = self.ipv6.router.lookup(dst) {
                    return Ok(v);
                } else {
                    tracing::error!(%src, %dst, "cannot find route");
                    tracing::debug!("{:#?}", self.ipv6.router)
                };
            }
            tracing::debug!("> default routers {:?}", self.ipv6.default_routers);

            self.ipv6
                .default_routers
                .next_router(&self.ipv6.neighbors)
                .map(|addr| (addr, None))
                .ok_or_else(|| io::Error::other("no router available"))
        }
    }

    pub fn ipv6_handle_timer(&mut self, msg: Message) -> io::Result<()> {
        use timer::TimerToken::*;
        let tokens = self.ipv6.timer.recv(&msg);

        for token in tokens {
            // tracing::debug!("timer exceeded: {token:?}");
            match token {
                PrefixTimeout { ifid, prefix } => {
                    self.ipv6_prefix_timeout(ifid, prefix)?;
                }

                RouterAdvertismentUnsolicited { ifid } => {
                    let cfg = self.ipv6.router_cfg.get(&ifid).unwrap();
                    if cfg.adv_send_advertisments {
                        self.ipv6_icmp_send_router_adv(ifid, Ipv6Addr::MULTICAST_ALL_NODES)?;
                        self.ipv6_schedule_unsolicited_router_adv(ifid)?;
                    }
                }
                RouterAdvertismentSolicited { ifid, dst } => {
                    self.ipv6_icmp_send_router_adv(ifid, dst)?;
                }
                NeighborSolicitationRetransmitTimeout { target, ifid } => {
                    self.ipv6_icmp_solicitation_retrans_timeout(target, ifid)?;
                }
                DelayedJoinMulticast { ifid, multicast } => {
                    let iface = self.ifaces.get_mut(&ifid).unwrap();
                    let _guard = tracing::span!(Level::INFO, "iface", id=%ifid).entered();
                    let needs_mld_report = iface.bindings.v6.join(multicast);

                    if needs_mld_report {
                        self.mld_on_event(ifid, NodeEvent::StartListening, multicast)?;
                    }
                }

                // MLD events
                MulticastListenerDiscoverySendReport {
                    ifid,
                    multicast_addr,
                } => self.mld_on_event(ifid, NodeEvent::TimerExpired, multicast_addr)?,
                MulticastListenerDiscoveryGeneralQuery { ifid } => {
                    self.mld_querier_on_event(ifid, RouterEvent::GeneralQueryTimerExpired)?;
                }
                MulticastListenerDiscoveryOtherQuerierPresent { ifid } => {
                    self.mld_querier_on_event(ifid, RouterEvent::OtherQueriesPresentTimerExpired)?;
                }
                MulticastListenerDiscoveryQuerierGroupTimer { ifid, addr } => {
                    self.mld_querier_on_event(
                        ifid,
                        RouterEvent::GroupEvent(addr, GroupEvent::TimerExpired),
                    )?;
                }
                MulticastListenerDiscoveryQuerierGroupRetransmissionTimer { ifid, addr } => {
                    self.mld_querier_on_event(
                        ifid,
                        RouterEvent::GroupEvent(addr, GroupEvent::RetransmitTimerExpired),
                    )?;
                }
            }
        }

        Ok(())
    }
}

// # Interface configuration

impl IOContext {
    pub fn ipv6_register_host_interface(&mut self, ifid: IfId) -> io::Result<()> {
        let _guard = tracing::span!(Level::INFO, "iface", id=%ifid).entered();
        self.ipv6.iface_state.insert(
            ifid,
            InterfaceState {
                link_mtu: 1500,
                cur_hop_limit: 64,
                base_reachable_time: Duration::from_secs(120),
                reachable_time: Duration::from_secs(120),
                retrans_timer: Duration::from_secs(30),
            },
        );

        self.ipv6_icmp_send_router_solicitation(ifid)
    }

    pub fn ipv6_prefix_timeout(&mut self, ifid: IfId, prefix: Ipv6Prefix) -> io::Result<()> {
        let _guard = tracing::span!(Level::INFO, "iface", id=%ifid).entered();
        tracing::debug!(%prefix, "prefix timed out");

        let timed_out = self.ipv6.prefixes.timeout();
        let iface = self.get_mut_iface(ifid)?;

        for timed_out in timed_out {
            // Delete relevant addrs on ifaces if nessecary
            let Some(assigned) = timed_out.assigned_addr else {
                continue;
            };
            let Some(binding) = iface.bindings.v6.remove(assigned) else {
                continue;
            };
            iface
                .bindings
                .v6
                .leave(Ipv6Addr::solicied_node_multicast(binding.addr));
        }

        Ok(())
    }
}
