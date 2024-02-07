use std::{io, net::Ipv6Addr, time::Duration};

use des::net::message::{schedule_in, Message};
use fxhash::{FxBuildHasher, FxHashMap};
use inet_types::ip::{ipv6_matches_subnet_len, Ipv6AddrExt, Ipv6Packet, KIND_IPV6};

use crate::{
    ctx::IOContext,
    interface::{IfId, InterfaceAddr},
};

use self::{
    addrs::PolicyTable,
    cfg::RouterInterfaceConfiguration,
    icmp::{ping::PingCtrl, tracerouter::TracerouteCB},
    ndp::{DefaultRouterList, DestinationCache, NeighborCache, PrefixList, Solicitations},
    router::{Router, RouterState},
    state::InterfaceState,
    timer::TimerCtrl,
};

pub mod addrs;
pub mod api;
pub mod cfg;
pub mod icmp;
pub mod ndp;
pub mod router;
pub mod state;
pub mod timer;
pub mod util;

pub struct Ipv6 {
    pub timer: TimerCtrl,

    pub solicitations: Solicitations,
    pub neighbors: NeighborCache,
    pub destinations: DestinationCache,
    pub prefixes: PrefixList,
    pub default_routers: DefaultRouterList,

    pub iface_state: FxHashMap<IfId, InterfaceState>,

    pub is_rooter: bool,
    pub router: Router,
    pub router_cfg: FxHashMap<IfId, RouterInterfaceConfiguration>,
    pub router_cfg_default: Option<RouterInterfaceConfiguration>,
    pub router_state: RouterState,

    pub policies: PolicyTable,

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

            iface_state: FxHashMap::with_hasher(FxBuildHasher::default()),

            is_rooter: false,
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

impl IOContext {
    pub fn ipv6_send(&mut self, mut pkt: Ipv6Packet, mut ifid: IfId) -> io::Result<()> {
        // self.send_ip_packet(
        //     SocketIfaceBinding::Bound(ifid),
        //     IpPacket::V6(pkt.clone()),
        //     true,
        // )?;

        // Assign src addr if nessecary
        if pkt.src.is_unspecified() {
            // (0) Check link local
            let canidates = self.ipv6_src_addr_canidate_set(pkt.dst, ifid);
            let Some(src) = canidates.select(&self.ipv6.policies) else {
                return Err(io::Error::new(io::ErrorKind::Other, "no valid src addr"));
            };
            pkt.src = src.addr;
        }

        // TODO:
        // make better self-send-detection
        if pkt.dst == pkt.src {
            // Try to send via lookback interface
            if let Some((_lo_ifid, lo_iface)) = self
                .ifaces
                .iter_mut()
                .find(|(_, iface)| iface.flags.loopback)
            {
                println!("lo fallback");
                lo_iface.send_buffered(Message::new().kind(KIND_IPV6).content(pkt).build())?;
                return Ok(());
            } else {
                // FIXME: dangerous since this execut4e directly
                println!("DANGER");
                let iface = self.ifaces.get(&ifid).unwrap();
                schedule_in(
                    Message::new()
                        .last_gate(iface.device.input().unwrap())
                        .kind(KIND_IPV6)
                        .src(iface.device.addr.into())
                        .dest(iface.device.addr.into())
                        .content(pkt)
                        .build(),
                    Duration::ZERO,
                );
                return Ok(());
            }
        }

        if ifid == IfId::NULL {
            ifid = self.ipv6_ifid_for_src_addr(pkt.src);
        }

        let next_hop = self.ipv6.destinations.lookup(pkt.dst, &self.ipv6.neighbors);
        let next_hop = if let Some(next_hop) = next_hop {
            next_hop
        } else {
            let (next_hop, new_ifid) = self.ipv6_next_hop_determination(pkt.src, pkt.dst, ifid)?;
            if new_ifid != IfId::NULL {
                ifid = new_ifid;
            }
            next_hop
        };

        // (3) Begin LL address resoloution
        let Some((mac, new_ifid)) = self.ipv6.neighbors.lookup(next_hop) else {
            self.ipv6_icmp_send_neighbor_solicitation(next_hop, ifid)?;
            self.ipv6.neighbors.enqueue(next_hop, pkt);
            return Ok(());
        };

        let ifid = if new_ifid == IfId::NULL {
            ifid
        } else {
            new_ifid
        };

        let iface = self.ifaces.get_mut(&ifid).unwrap();
        let msg = Message::new()
            .src(iface.device.addr.into())
            .dest(mac.into())
            .kind(KIND_IPV6)
            .content(pkt)
            .build();

        iface.send_buffered(msg)
    }

    fn ipv6_ifid_for_src_addr(&self, src: Ipv6Addr) -> IfId {
        for (id, iface) in &self.ifaces {
            if iface.addrs.ipv6_addrs().contains(&src) {
                return *id;
            }
        }

        panic!("Could not specified addr")
    }

    fn ipv6_next_hop_determination(
        &mut self,
        src: Ipv6Addr,
        dst: Ipv6Addr,
        _ifid: IfId,
    ) -> io::Result<(Ipv6Addr, IfId)> {
        if let Some(next_hop) = self.ipv6.prefixes.next_hop_determination(dst) {
            tracing::trace!("cached next hop {next_hop} for destination {dst}");
            self.ipv6.destinations.set(dst, next_hop);
            Ok((next_hop, IfId::NULL))
        } else {
            if self.ipv6.is_rooter {
                if let Some(v) = self.ipv6.router.lookup(dst) {
                    return Ok(v);
                } else {
                    tracing::error!(%src, %dst, "cannot find route");
                };
            }
            self.ipv6
                .default_routers
                .next_router(&self.ipv6.neighbors)
                .map(|addr| (addr, IfId::NULL))
                .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "no router available"))
        }
    }

    pub fn ipv6_handle_timer(&mut self, msg: Message) {
        use timer::TimerToken::*;
        let tokens = self.ipv6.timer.recv(&msg);
        for token in tokens {
            // tracing::debug!("timer exceeded: {token:?}");
            match token {
                NeighborSolicitationRetransmitTimeout { target, ifid } => {
                    self.ipv6_icmp_solicitation_retrans_timeout(target, ifid)
                        .unwrap();
                }
            }
        }
    }
}

// # Interface configuration

impl IOContext {
    pub fn ipv6_register_host_interface(&mut self, ifid: IfId) {
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
    }

    pub fn ipv6_register_new_iface_addr(&mut self, ifid: IfId, addr: Ipv6Addr) -> io::Result<()> {
        // will send unsolicited neighbor advertismetns
        self.ipv6_icmp_send_unsolicited_adv(ifid, addr)?;
        Ok(())
    }
}
