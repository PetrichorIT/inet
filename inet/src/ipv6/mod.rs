use std::{io, time::Duration};

use fxhash::{FxBuildHasher, FxHashMap};
use inet_types::ip::{IpPacket, Ipv6Packet};

use crate::{ctx::IOContext, interface::IfId, socket::SocketIfaceBinding};

use self::{
    cfg::RouterInterfaceConfiguration,
    state::{DefaultRouterList, DestinationCache, InterfaceState, NeighborCache, PrefixList},
};

pub mod cfg;
pub mod icmp;
pub mod state;

pub struct Ipv6 {
    pub neighbors: NeighborCache,
    pub destinations: DestinationCache,
    pub prefixes: PrefixList,
    pub default_routers: DefaultRouterList,

    pub is_rooter: bool,
    pub router_cfg: FxHashMap<IfId, RouterInterfaceConfiguration>,
    pub iface_state: FxHashMap<IfId, InterfaceState>,
}

impl Ipv6 {
    pub fn new() -> Self {
        Ipv6 {
            neighbors: NeighborCache::default(),
            destinations: DestinationCache::default(),
            prefixes: PrefixList::default(),
            default_routers: DefaultRouterList::new(),

            is_rooter: false,

            router_cfg: FxHashMap::with_hasher(FxBuildHasher::default()),
            iface_state: FxHashMap::with_hasher(FxBuildHasher::default()),
        }
    }
}

impl IOContext {
    fn ipv6_send(&mut self, pkt: Ipv6Packet, ifid: IfId) -> io::Result<()> {
        self.send_ip_packet(SocketIfaceBinding::Bound(ifid), IpPacket::V6(pkt), true)
    }

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
}
