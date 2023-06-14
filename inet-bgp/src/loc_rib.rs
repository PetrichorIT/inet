use des::time::SimTime;
use fxhash::{FxBuildHasher, FxHashMap};

use crate::{
    adj_in::{Route, RouteId},
    adj_rib_out::{AdjRIBOut, RIBEntry},
    pkt::Nlri,
    BgpNodeInformation,
};

pub struct LocRib {
    destinations: FxHashMap<Nlri, (RouteId, Meta)>,
    routes: FxHashMap<RouteId, Route>,
}

pub struct Meta {
    written_to_table: bool,
}

impl LocRib {
    pub fn new() -> LocRib {
        Self {
            destinations: FxHashMap::with_hasher(FxBuildHasher::default()),
            routes: FxHashMap::with_hasher(FxBuildHasher::default()),
        }
    }

    pub fn add_dest(&mut self, dest: Nlri, route: &Route) {
        if self.routes.get(&route.id).is_none() {
            self.routes.insert(route.id, route.clone());
        }

        self.destinations.insert(
            dest,
            (
                route.id,
                Meta {
                    written_to_table: false,
                },
            ),
        );
    }

    pub fn lookup(&self, dest: Nlri) -> Option<&Route> {
        self.destinations
            .get(&dest)
            .map(|(id, _)| self.routes.get(id))
            .flatten()
    }

    pub fn advertise_dest(&self, dest: Nlri, out: &mut AdjRIBOut) {
        let Some(route) = self.lookup(dest) else { return };
        out.publish_all(RIBEntry {
            nlri: vec![dest],
            next_hop: route.peer.next_hop,
            path: route.path.clone(),
            flag: false,
            ts: SimTime::now(),
        })
    }

    pub fn psh_publish(&self, peer: &BgpNodeInformation, out: &mut AdjRIBOut) {
        // Reverse lookups

        let mut nlris = self
            .destinations
            .iter()
            .map(|(d, (id, _))| (*d, *id))
            .collect::<Vec<_>>();
        nlris.sort_by(|l, r| l.1.cmp(&r.1));

        for (id, route) in &self.routes {
            let Ok(mut i) = nlris.binary_search_by(|v| v.1.cmp(id)) else {
                continue;
            };

            // begin of list
            while i > 0 {
                if nlris[i - 1].1 != *id {
                    break;
                }
                i -= 1;
            }
            let mut pubs = Vec::new();

            while i < nlris.len() {
                if nlris[i].1 != *id {
                    break;
                }
                pubs.push(nlris[i].0);
                i += 1;
            }

            out.publish(
                RIBEntry {
                    nlri: pubs,
                    next_hop: route.peer.next_hop,
                    path: route.path.clone(),
                    flag: false,
                    ts: SimTime::now(),
                },
                peer.addr,
            );
        }
    }
}
