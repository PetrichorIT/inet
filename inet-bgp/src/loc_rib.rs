use std::{
    mem,
    ops::{Deref, DerefMut},
};

use des::time::SimTime;
use fxhash::{FxBuildHasher, FxHashMap};
use inet::routing::RoutingTableId;

use crate::{
    adj_in::{AdjIn, Peer, PeerId, Route, RouteId},
    adj_out::{AdjRIBOut, RIBEntry},
    kernel::Kernel,
    pkt::Nlri,
    BgpNodeInformation,
};

pub struct LocRibWithKernel {
    loc_rib: LocRib,
    kernel: Box<dyn Kernel>,
}

impl LocRibWithKernel {
    pub fn new(table_id: RoutingTableId, kernel: Box<dyn Kernel>) -> Self {
        Self {
            loc_rib: LocRib::new(table_id),
            kernel,
        }
    }
    pub fn kernel_decision(&mut self, adj_in: &AdjIn, adj_out: &mut AdjRIBOut) -> bool {
        self.kernel.decision(adj_in, &mut self.loc_rib, adj_out)
    }
}

impl Deref for LocRibWithKernel {
    type Target = LocRib;
    fn deref(&self) -> &Self::Target {
        &self.loc_rib
    }
}

impl DerefMut for LocRibWithKernel {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.loc_rib
    }
}

#[derive(Debug)]
pub struct LocRib {
    dests: FxHashMap<Nlri, (RouteId, Meta)>,
    routes: FxHashMap<RouteId, (Route, Peer)>,
    pub pending: Vec<Nlri>,
    #[allow(unused)]
    table_id: RoutingTableId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Meta {
    written_to_table: bool,
}

impl LocRib {
    pub fn new(table_id: RoutingTableId) -> LocRib {
        Self {
            dests: FxHashMap::with_hasher(FxBuildHasher::default()),
            routes: FxHashMap::with_hasher(FxBuildHasher::default()),
            pending: Vec::new(),
            table_id,
        }
    }

    pub fn status(&self) {
        let dest = self.dests.iter().map(|v| v.clone()).collect::<Vec<_>>();
        tracing::debug!("[ LOC RIB ]");
        for (d, (i, _)) in dest {
            let (r, p) = self.routes.get(i).unwrap();
            tracing::debug!(" {d:?} via {} ({r})", p.next_hop);
        }
    }

    pub fn pending(&mut self) -> Vec<Nlri> {
        let mut swp = Vec::new();
        mem::swap(&mut swp, &mut self.pending);
        swp
    }

    pub fn add_dest(&mut self, dest: Nlri, route: &Route, peer: &Peer) {
        if self.routes.get(&route.id).is_none() {
            self.routes.insert(route.id, (route.clone(), peer.clone()));
        }

        self.dests.insert(
            dest,
            (
                route.id,
                Meta {
                    written_to_table: false,
                },
            ),
        );
        self.routes.get_mut(&route.id).expect("failed").0.ucount += 1;

        // tracing::info!("{dest:?} {route:?}");
        // if &*peer.iface != "invalid" {
        //     tracing::error!(
        //         "{} & {} || {} ({})",
        //         dest.prefix(),
        //         dest.netmask(),
        //         peer.next_hop,
        //         &*peer.iface
        //     );
        //     inet::routing::add_routing_entry_to(
        //         dest.prefix(),
        //         dest.netmask(),
        //         peer.next_hop,
        //         &*peer.iface,
        //         self.table_id,
        //     )
        //     .expect("failed to set route to table");
        // }
    }

    /// Call this function if
    /// - a dest from the adj_in is no longer rechable via a given peer,
    pub fn withdraw_canidate(&mut self, dest: &Nlri, dead_peer: &PeerId) {
        // (0) Check whether LOC even uses this route.
        let Some((_, peer)) = self.lookup(*dest) else {
            tracing::error!("trying to withdraw dest {dest:?} via {dead_peer}");
            todo!()
        };

        if peer.next_hop != *dead_peer {
            // route selection remains safe
            return;
        }

        // (1) Remove destination, and route if nessecary
        self.remove_dest(dest);

        // (2) Marks as pending recalc
        self.pending.push(*dest);
    }

    pub fn remove_dest(&mut self, nlri: &Nlri) {
        let Some((route_id, _)) = self.dests.remove(nlri) else {
            todo!()
        };

        let Some((route, _)) = self.routes.get_mut(&route_id) else {
            todo!()
        };

        route.ucount = route.ucount.saturating_sub(1);
        if route.ucount == 0 {
            self.routes.remove(&route_id);
        }
    }

    pub fn lookup(&self, dest: Nlri) -> Option<&(Route, Peer)> {
        self.dests
            .get(&dest)
            .map(|(id, _)| self.routes.get(id))
            .flatten()
    }

    pub fn lookup_mut(&mut self, dest: Nlri) -> Option<&mut (Route, Peer)> {
        self.dests
            .get(&dest)
            .map(|(id, _)| self.routes.get_mut(id))
            .flatten()
    }

    pub fn advertise_dest(&self, dest: Nlri, out: &mut AdjRIBOut) {
        let Some((route, peer)) = self.lookup(dest) else { return };
        out.advertise_to_all(RIBEntry {
            nlri: vec![dest],
            next_hop: peer.next_hop,
            path: route.path.clone(),
            flag: false,
            ts: SimTime::now(),
        })
    }

    pub fn withdraw_and_advertise_new(&self, dest: Nlri, out: &mut AdjRIBOut) {
        let Some((route, peer)) = self.lookup(dest) else { return };
        out.withdraw_and_adverise(dest, route, peer);
    }

    pub fn psh_publish(&self, peer: &BgpNodeInformation, out: &mut AdjRIBOut) {
        // Reverse lookups

        let mut nlris = self
            .dests
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

            out.advertise_to(
                RIBEntry {
                    nlri: pubs,
                    next_hop: route.1.next_hop,
                    path: route.0.path.clone(),
                    flag: false,
                    ts: SimTime::now(),
                },
                peer.addr,
            );
        }
    }
}

// impl Drop for LocRib {
//     fn drop(&mut self) {
//         let keys = self.dests.keys().cloned().collect::<Vec<_>>();
//         for key in keys {
//             tracing::info!("{key:?} :: {:?}", self.lookup(key).unwrap())
//         }
//     }
// }
