use std::{fmt::Display, net::Ipv4Addr};

use des::time::SimTime;
use fxhash::{FxBuildHasher, FxHashMap, FxHashSet};
use inet::interface::InterfaceName;

use crate::{
    BgpNodeInformation,
    pkt::{BgpPathAttribute, BgpPathAttributeKind, BgpUpdatePacket, Nlri},
    types::AsNumber,
};

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct AdjIn {
    routes_id: RouteId,
    dirty: bool,
    peers: FxHashMap<PeerId, AdjPeerIn>,
    updated: FxHashSet<(Nlri, PeerId)>,
    withdrawn: FxHashSet<(Nlri, PeerId)>,
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
    #[must_use]
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
    #[must_use]
    pub fn new() -> Self {
        Self {
            peers: FxHashMap::with_hasher(FxBuildHasher::default()),
            routes_id: 0,
            dirty: false,
            updated: FxHashSet::with_hasher(FxBuildHasher::default()),
            withdrawn: FxHashSet::with_hasher(FxBuildHasher::default()),
        }
    }

    #[allow(clippy::missing_panics_doc)]
    pub fn status(&self) {
        tracing::debug!("[ BGP ADJ IN ]");
        for (peer, adj) in &self.peers {
            tracing::debug!("Peer({peer:?})");
            for (dest, id) in adj.dests.iter().collect::<Vec<_>>() {
                tracing::debug!(" {dest:?} via {} ({})", peer, adj.routes.get(id).unwrap());
            }
        }
    }

    #[must_use]
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

    /// # Panics
    ///
    /// Panics if the peer does not exist.
    pub fn unregister(&mut self, peer: &BgpNodeInformation) {
        let adj_peer = self
            .peers
            .remove(&peer.addr)
            .expect("unregistered not existing");

        self.withdrawn
            .extend(adj_peer.dests.keys().map(|d| (*d, adj_peer.peer.next_hop)));
    }

    /// # Panics
    ///
    /// Panics if the peer table does not exist.
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

            self.withdrawn.insert((withdrawn, peer_addr));
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
                    return;
                };

                old_route.ucount = old_route.ucount.saturating_sub(1);
                if old_route.ucount == 0 {
                    adj_table.routes.remove(&old_route_id);
                }
            } else {
                adj_table.dests.insert(nlri, id);
                route.ucount += 1;
            }

            self.updated.insert((nlri, adj_table.peer.next_hop));
            self.dirty |= true;
        }

        if route.ucount > 0 {
            adj_table.routes.insert(id, route);
        }
    }

    #[allow(clippy::missing_panics_doc)]
    pub fn routes_to(&self, dest: Nlri) -> impl Iterator<Item = (&Route, &Peer)> {
        self.peers.values().filter_map(move |peer_adj| {
            peer_adj.dests.get(&dest).map(|route_id| {
                (
                    peer_adj
                        .routes
                        .get(route_id)
                        .expect("internal mapping error"),
                    &peer_adj.peer,
                )
            })
        })
    }

    #[allow(clippy::missing_panics_doc)]
    pub fn routes(&self) -> impl Iterator<Item = (&Nlri, &Route, &Peer)> {
        self.peers.values().flat_map(|peer_adj| {
            peer_adj.dests.iter().map(|(k, v)| {
                (
                    k,
                    peer_adj.routes.get(v).expect("internal mapping error"),
                    &peer_adj.peer,
                )
            })
        })
    }

    #[allow(clippy::missing_panics_doc)]
    pub fn updated_routes(&self) -> impl Iterator<Item = (&Nlri, &Route, &Peer)> {
        self.updated.iter().filter_map(|(dest, peer)| {
            let peer_adj = self.peers.get(peer)?;
            let route_id = peer_adj.dests.get(dest).expect("failed");
            let route = peer_adj.routes.get(route_id).expect("failed");

            Some((dest, route, &peer_adj.peer))
        })
    }

    pub fn withdrawn_routes(&self) -> impl Iterator<Item = &(Nlri, PeerId)> {
        self.withdrawn.iter()
    }
}

impl Route {
    #[must_use]
    pub fn is_as_on_path(&self, as_num: AsNumber) -> bool {
        for attr in &self.path {
            if let BgpPathAttributeKind::AsPath(ref as_attr) = attr.attr
                && as_attr.path.contains(&as_num)
            {
                return true;
            }
        }

        false
    }
}

impl Display for Route {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for attr in &self.path {
            match &attr.attr {
                BgpPathAttributeKind::Origin(origin) => write!(f, "ORIGIN({origin:?}),"),
                BgpPathAttributeKind::AsPath(path) => write!(f, "ASPATH({:?}),", path.path),
                BgpPathAttributeKind::NextHop(hop) => write!(f, "NEXT({:?}),", hop.hop),
            }?;
        }
        Ok(())
    }
}
