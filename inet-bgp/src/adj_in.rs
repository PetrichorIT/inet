use std::net::Ipv4Addr;

use des::time::SimTime;
use fxhash::{FxBuildHasher, FxHashMap};
use inet::interface::InterfaceName;

use crate::{
    pkt::{BgpPathAttribute, BgpUpdatePacket, Nlri},
    types::AsNumber,
    BgpNodeInformation,
};

pub struct AdjIn {
    destinations: FxHashMap<Nlri, RouteId>,
    routes: FxHashMap<RouteId, Route>,
    routes_id: RouteId,
    peers: Vec<Peer>,
    dirty: bool,
}

pub type RouteId = usize;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Route {
    pub id: RouteId,
    pub peer: Peer,
    pub path: Vec<BgpPathAttribute>,
    pub ts: SimTime,
    pub new_route: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Peer {
    pub as_num: AsNumber,
    pub next_hop: Ipv4Addr,
    pub iface: InterfaceName,
}

impl AdjIn {
    pub fn new() -> Self {
        Self {
            destinations: FxHashMap::with_hasher(FxBuildHasher::default()),
            routes: FxHashMap::with_hasher(FxBuildHasher::default()),
            routes_id: 0,
            peers: Vec::new(),
            dirty: false,
        }
    }

    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    pub fn unset_dirty(&mut self) {
        self.dirty &= false;
        for route in self.routes.values_mut() {
            route.new_route = false;
        }
    }

    pub fn register(&mut self, peer: &BgpNodeInformation) {
        self.peers.push(Peer {
            as_num: peer.as_num,
            next_hop: peer.addr,
            iface: peer.iface.clone(),
        })
    }

    pub fn unregister(&mut self, peer: &BgpNodeInformation) {
        let peer = Peer {
            as_num: peer.as_num,
            next_hop: peer.addr,
            iface: peer.iface.clone(),
        };
        self.peers.retain(|p| *p != peer)
    }

    pub fn process(&mut self, update: BgpUpdatePacket, peer: Ipv4Addr) {
        // create new route entry
        let id = self.routes_id;
        self.routes_id = self.routes_id.wrapping_add(4) & !0b1;
        assert_ne!(id, self.routes_id);

        let route = Route {
            id,
            peer: self.peer(peer).cloned().expect("invalid peer"),
            path: update.path_attributes,
            ts: SimTime::now(),
            new_route: true,
        };
        let mut usages = 0;

        for nlri in update.nlris {
            if let Some(_) = self.lookup(nlri) {
                *self.destinations.get_mut(&nlri).expect("unreachable") = id;
                usages += 1;
            } else {
                self.destinations.insert(nlri, id);
                usages += 1
            }
        }

        if usages > 0 {
            self.routes.insert(id, route);
            self.dirty |= true;
        }
    }

    fn lookup(&self, dest: Nlri) -> Option<&Route> {
        let id = self.destinations.get(&dest)?;
        self.routes.get(id)
    }

    fn peer(&self, addr: Ipv4Addr) -> Option<&Peer> {
        self.peers.iter().find(|p| p.next_hop == addr)
    }

    pub fn dests(&self) -> &FxHashMap<Nlri, RouteId> {
        &self.destinations
    }

    pub fn routes(&self) -> &FxHashMap<RouteId, Route> {
        &self.routes
    }

    pub fn paths(&self) -> impl Iterator<Item = (Nlri, &Route)> {
        self.destinations
            .iter()
            .map(|(dest, id)| (*dest, self.routes.get(id).unwrap()))
    }
}
