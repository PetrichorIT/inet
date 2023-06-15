use std::net::Ipv4Addr;

use crate::{adj_in::AdjIn, adj_out::AdjRIBOut, loc_rib::LocRib};

pub trait Kernel: Send {
    fn decision(&mut self, adj_in: &AdjIn, loc_rib: &mut LocRib, adj_out: &mut AdjRIBOut) -> bool;
}

pub(super) struct DefaultBgpKernel;
impl Kernel for DefaultBgpKernel {
    fn decision(&mut self, adj_in: &AdjIn, loc_rib: &mut LocRib, adj_out: &mut AdjRIBOut) -> bool {
        for (dest, peer) in adj_in.withdrawn_routes() {
            loc_rib.withdraw_canidate(dest, peer)
        }

        for (&dest, path, peer) in adj_in.updated_routes() {
            if loc_rib.lookup(dest).is_none() {
                tracing::info!("new NLR {dest:?} via {}", peer);
                loc_rib.add_dest(dest, path, peer);
                loc_rib.advertise_dest(dest, adj_out);
            }
        }

        for dest in loc_rib.pending() {
            // This route was lost, establish a new one or withdraw
            let route = adj_in
                .routes_to(dest)
                .min_by(|(l, _), (r, _)| l.as_path_len().cmp(&r.as_path_len()));

            if let Some((route, peer)) = route {
                loc_rib.add_dest(dest, route, peer);
                tracing::info!("updated NLR {dest:?} via {peer}")
            } else {
                tracing::info!("lost NLR {dest:?}");
                adj_out.withdraw_dest(dest);
            }
        }

        true
    }
}
