use std::{fmt::Display, net::Ipv4Addr};

use des::time::SimTime;
use fxhash::{FxBuildHasher, FxHashMap};
use inet::interface::InterfaceName;

use crate::{
    pkt::{BgpPathAttribute, BgpPathAttributeKind, BgpUpdatePacket, Nlri},
    types::AsNumber,
    BgpNodeInformation,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdjIn {
    routes_id: RouteId,
    dirty: bool,
    peers: FxHashMap<PeerId, AdjPeerIn>,
    updated: Vec<(Nlri, PeerId)>,
    withdrawn: Vec<(Nlri, PeerId)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AdjPeerIn {
    peer: Peer,
    dests: FxHashMap<Nlri, RouteId>,
    routes: FxHashMap<RouteId, Route>,
}

pub type RouteId = usize;
pub type PeerId = Ipv4Addr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Route {
    pub id: RouteId,
    pub path: Vec<BgpPathAttribute>,
    pub ts: SimTime,
    pub ucount: usize,
}

impl Route {
    pub fn as_path_len(&self) -> usize {
        self.path
            .iter()
            .find_map(|a| {
                if let BgpPathAttributeKind::AsPath(ref path) = a.attr {
                    Some(path.path.len())
                } else {
                    None
                }
            })
            .unwrap_or(0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Peer {
    pub as_num: AsNumber,
    pub next_hop: Ipv4Addr,
    pub iface: InterfaceName,
}

impl Display for Peer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}[{}]", self.next_hop, self.as_num, self.iface)
    }
}

impl AdjIn {
    pub fn new() -> Self {
        Self {
            peers: FxHashMap::with_hasher(FxBuildHasher::default()),
            routes_id: 0,
            dirty: false,
            updated: Vec::new(),
            withdrawn: Vec::new(),
        }
    }

    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    pub fn unset_dirty(&mut self) {
        self.dirty &= false;
        self.updated.clear();
        self.withdrawn.clear();
    }

    pub fn register(&mut self, peer: &BgpNodeInformation) {
        self.peers.insert(
            peer.addr,
            AdjPeerIn {
                peer: Peer {
                    as_num: peer.as_num,
                    next_hop: peer.addr,
                    iface: peer.iface.clone(),
                },
                dests: FxHashMap::with_hasher(FxBuildHasher::default()),
                routes: FxHashMap::with_hasher(FxBuildHasher::default()),
            },
        );
    }

    pub fn unregister(&mut self, peer: &BgpNodeInformation) {
        let adj_peer = self
            .peers
            .remove(&peer.addr)
            .expect("unregistered not existing");

        self.withdrawn
            .extend(adj_peer.dests.keys().map(|d| (*d, adj_peer.peer.next_hop)))
    }

    pub fn process(&mut self, update: BgpUpdatePacket, peer_addr: Ipv4Addr) {
        let Some(adj_table) = self.peers.get_mut(&peer_addr) else {
            todo!()
        };

        // create new route entry
        let id = self.routes_id;
        self.routes_id = self.routes_id.wrapping_add(4) & !0b1;
        assert_ne!(id, self.routes_id);

        for withdrawn in update.withdrawn_routes {
            let Some(route_id) = adj_table.dests.remove(&withdrawn) else {
                todo!();
            };
            let Some(route) = adj_table.routes.get_mut(&route_id) else {
                todo!()
            };
            route.ucount = route.ucount.saturating_sub(1);
            if route.ucount == 0 {
                adj_table.routes.remove(&route_id);
            }

            self.withdrawn.push((withdrawn, peer_addr));
            self.dirty |= true;
        }

        let mut route = Route {
            id,
            path: update.path_attributes,
            ts: SimTime::now(),
            ucount: 0,
        };

        for nlri in update.nlris {
            if let Some(d_route_id) = adj_table.dests.get_mut(&nlri) {
                let old_route_id: usize = *d_route_id;
                *d_route_id = id;
                route.ucount += 1;

                let Some(old_route) = adj_table.routes.get_mut(&old_route_id) else {
                    return
                };

                old_route.ucount = old_route.ucount.saturating_sub(1);
                if old_route.ucount == 0 {
                    adj_table.routes.remove(&old_route_id);
                }
            } else {
                adj_table.dests.insert(nlri, id);
                route.ucount += 1
            }

            self.updated.push((nlri, adj_table.peer.next_hop));
            self.dirty |= true;
        }

        if route.ucount > 0 {
            adj_table.routes.insert(id, route);
        }
    }

    pub fn routes_to(&self, dest: Nlri) -> impl Iterator<Item = (&Route, &Peer)> {
        self.peers
            .values()
            .map(move |peer_adj| {
                if let Some(route_id) = peer_adj.dests.get(&dest) {
                    Some((
                        peer_adj
                            .routes
                            .get(route_id)
                            .expect("internal mapping error"),
                        &peer_adj.peer,
                    ))
                } else {
                    None
                }
            })
            .flatten()
    }

    pub fn routes(&self) -> impl Iterator<Item = (&Nlri, &Route, &Peer)> {
        self.peers
            .values()
            .map(|peer_adj| {
                peer_adj.dests.iter().map(|(k, v)| {
                    (
                        k,
                        peer_adj.routes.get(v).expect("internal mapping error"),
                        &peer_adj.peer,
                    )
                })
            })
            .flatten()
    }

    pub fn updated_routes(&self) -> impl Iterator<Item = (&Nlri, &Route, &Peer)> {
        self.updated
            .iter()
            .map(|(dest, peer)| {
                let Some(peer_adj) = self.peers.get(peer) else {
                return None
            };
                let route_id = peer_adj.dests.get(dest).expect("failed");
                let route = peer_adj.routes.get(&route_id).expect("failed");

                Some((dest, route, &peer_adj.peer))
            })
            .flatten()
    }

    pub fn withdrawn_routes(&self) -> impl Iterator<Item = &(Nlri, PeerId)> {
        self.withdrawn.iter()
    }
}
