use des::time::SimTime;

use crate::{adj_in::AdjIn, adj_out::AdjRIBOut, loc_rib::LocRib, BgpNodeInformation};

pub trait Kernel: Send {
    fn decision(&mut self, adj_in: &AdjIn, loc_rib: &mut LocRib, adj_out: &mut AdjRIBOut) -> bool;
}

pub(super) struct DefaultBgpKernel(pub(super) BgpNodeInformation);
impl Kernel for DefaultBgpKernel {
    fn decision(&mut self, adj_in: &AdjIn, loc_rib: &mut LocRib, adj_out: &mut AdjRIBOut) -> bool {
        // if SimTime::now().as_secs() == 200 && module_name() == "bgp_d_1" {
        //     dbg!(adj_in);
        // }

        for (dest, peer) in adj_in.withdrawn_routes() {
            loc_rib.withdraw_canidate(dest, peer)
        }

        for (&dest, path, peer) in adj_in.updated_routes() {
            if let Some((e_path, e_peer)) = loc_rib.lookup_mut(dest) {
                // (0) Route may be updated, but only if previous route becomes invalid
                if e_peer != peer {
                    if path.as_path_len() < e_path.as_path_len() {
                        tracing::info!("[1] updating NLR {dest:?} via {peer}");
                        loc_rib.remove_dest(&dest);
                        loc_rib.add_dest(dest, path, peer);
                        loc_rib.advertise_dest(dest, adj_out);
                    }
                } else {
                    //  update to used path
                    // and update will not worsen the path thus only update the peering
                    e_path.path = path.path.clone();
                    e_path.ts = SimTime::now();
                    loc_rib.advertise_dest(dest, adj_out);
                }
            } else {
                tracing::info!("new NLR {dest:?} via {}", peer);
                loc_rib.add_dest(dest, path, peer);
                loc_rib.advertise_dest(dest, adj_out);
            }
        }

        for dest in loc_rib.pending() {
            // This route was lost, establish a new one or withdraw
            let route = adj_in
                .routes_to(dest)
                .filter(|(r, _)| !r.is_as_on_path(self.0.as_num))
                .min_by(|(l, _), (r, _)| l.as_path_len().cmp(&r.as_path_len()));

            if let Some((route, peer)) = route {
                loc_rib.add_dest(dest, route, peer);
                loc_rib.withdraw_and_advertise_new(dest, adj_out);
                tracing::info!("updated NLR {dest:?} via {peer}")
            } else {
                tracing::info!("lost NLR {dest:?}");
                adj_out.withdraw_dest(dest);
            }
        }

        true
    }
}
