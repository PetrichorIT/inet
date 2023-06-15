use des::time::SimTime;
use fxhash::{FxBuildHasher, FxHashMap};
use std::{future::pending, net::Ipv4Addr};
use tokio::sync::mpsc::Sender;

use crate::{
    peering::NeighborHandle,
    pkt::{BgpPathAttributeNextHop, BgpPathAttributeOrigin, BgpUpdatePacket},
    BgpNodeInformation, NeighborEgressEvent,
};
use crate::{
    pkt::{
        BgpPathAttribute, BgpPathAttributeAsPath, BgpPathAttributeAsPathTyp, BgpPathAttributeFlags,
        BgpPathAttributeKind, Nlri,
    },
    types::AsNumber,
};

pub struct AdjRIBOut {
    ribs: FxHashMap<Ipv4Addr, AdjOut>,
    host_info: BgpNodeInformation,
    dirty: bool,
}

struct AdjOut {
    rib: RoutingInformationBase,
    withdrawn: Vec<RIBEntry>,
    dirty: bool,
    info: BgpNodeInformation,
    tx: Sender<NeighborEgressEvent>,
}

impl AdjRIBOut {
    pub fn new(host_info: BgpNodeInformation) -> Self {
        Self {
            ribs: FxHashMap::with_hasher(FxBuildHasher::default()),
            dirty: false,
            host_info,
        }
    }

    pub(super) fn register(
        &mut self,
        peer: &BgpNodeInformation,
        map: &FxHashMap<Ipv4Addr, NeighborHandle>,
    ) {
        self.ribs.insert(
            peer.addr,
            AdjOut {
                tx: map.get(&peer.addr).expect("no handle").tx.clone(),
                rib: RoutingInformationBase::new(),
                info: peer.clone(),
                withdrawn: Vec::new(),
                dirty: false,
            },
        );
    }

    pub(super) fn unregister(&mut self, peer: &BgpNodeInformation) {
        self.ribs.remove(&peer.addr);
    }

    pub(super) fn advertise_to_all(&mut self, entry: RIBEntry) {
        let keys = self.ribs.keys().copied().collect::<Vec<_>>();
        for key in keys {
            self.advertise_to(entry.clone(), key);
        }
    }

    pub(super) fn advertise_to(&mut self, mut entry: RIBEntry, peer: Ipv4Addr) {
        let Some(rib) = self.ribs.get_mut(&peer) else { todo!() };
        if entry.is_as_on_path(rib.info.as_num) {
            return;
        }

        let origin = if rib.info.as_num == self.host_info.as_num {
            BgpPathAttributeOrigin::Igp
        } else {
            BgpPathAttributeOrigin::Egp
        };

        entry.flag = false; // flag represents whether entry was allready advertised
        entry.add_path_as(self.host_info.as_num, origin);
        if origin == BgpPathAttributeOrigin::Egp {
            entry.set_next_hop(self.host_info.addr);
        }

        rib.rib.add(entry);
        rib.dirty = true;

        self.dirty = true;
    }

    pub fn withdraw_dest(&mut self, dest: Nlri) {
        for rib in self.ribs.values_mut() {
            let Some(mut entry) = rib.rib.withdraw(dest) else {
                continue;
            };

            if entry.is_as_on_path(rib.info.as_num) {
                // Was not adverised either way
                return;
            }

            entry.flag = false;
            entry.add_path_as(
                self.host_info.as_num,
                if rib.info.as_num == self.host_info.as_num {
                    BgpPathAttributeOrigin::Igp
                } else {
                    BgpPathAttributeOrigin::Egp
                },
            );

            rib.withdrawn.push(entry);
            rib.dirty |= true;
            self.dirty |= true;
        }
    }

    pub(super) async fn tick(&mut self) {
        // tracing::info!("tick");

        if !self.dirty {
            return pending::<()>().await;
        }

        for (
            peer,
            AdjOut {
                rib,
                dirty,
                tx,
                withdrawn,
                ..
            },
        ) in &mut self.ribs
        {
            if !*dirty {
                continue;
            }

            for entry in withdrawn {
                if !entry.flag {
                    tx.send(NeighborEgressEvent::Advertise(entry.to_withdraw()))
                        .await
                        .expect("Failed");

                    entry.flag = true;
                }
            }

            for entry in rib.entries_mut() {
                if !entry.flag {
                    tx.send(NeighborEgressEvent::Advertise(entry.to_update()))
                        .await
                        .expect("Failed");

                    entry.flag = true;
                }
            }

            *dirty = false;
        }

        self.dirty = false;
    }
}

pub struct RoutingInformationBase {
    mapping: Vec<RIBEntry>,
}

#[derive(Debug, Clone)]
pub struct RIBEntry {
    pub nlri: Vec<Nlri>,
    pub next_hop: Ipv4Addr, // Also id of the advertising router
    pub path: Vec<BgpPathAttribute>,
    pub flag: bool,
    pub ts: SimTime,
}

impl RoutingInformationBase {
    pub fn new() -> Self {
        Self {
            mapping: Vec::new(),
        }
    }

    pub fn entries(&self) -> &[RIBEntry] {
        &self.mapping
    }

    pub fn lookup(&self, nlri: Nlri) -> Option<&RIBEntry> {
        self.mapping.iter().find(|e| e.nlri.contains(&nlri))
    }

    pub fn lookup_mut(&mut self, nlri: Nlri) -> Option<&mut RIBEntry> {
        self.mapping.iter_mut().find(|e| e.nlri.contains(&nlri))
    }

    pub fn entries_mut(&mut self) -> &mut [RIBEntry] {
        &mut self.mapping
    }

    pub fn withdraw(&mut self, dest: Nlri) -> Option<RIBEntry> {
        let (i, _) = self
            .mapping
            .iter()
            .enumerate()
            .find(|(_, v)| v.nlri.contains(&dest))?;
        Some(self.mapping.remove(i))
    }

    pub fn add(&mut self, entry: RIBEntry) {
        self.mapping.push(entry)
    }
}

impl RIBEntry {
    pub fn to_update(&self) -> BgpUpdatePacket {
        let path_attributes = self.path.clone();
        BgpUpdatePacket {
            withdrawn_routes: Vec::new(),
            path_attributes,
            nlris: self.nlri.clone(),
        }
    }

    pub fn to_withdraw(&self) -> BgpUpdatePacket {
        let path_attributes = self.path.clone();
        BgpUpdatePacket {
            withdrawn_routes: self.nlri.clone(),
            path_attributes,
            nlris: Vec::new(),
        }
    }

    pub fn is_as_on_path(&self, as_num: AsNumber) -> bool {
        for attr in &self.path {
            if let BgpPathAttributeKind::AsPath(ref as_attr) = attr.attr {
                if as_attr.path.contains(&as_num) {
                    return true;
                }
            }
        }

        false
    }

    pub fn set_next_hop(&mut self, next_hop: Ipv4Addr) {
        for attr in self.path.iter_mut() {
            if let BgpPathAttributeKind::NextHop(ref mut hop) = attr.attr {
                hop.hop = next_hop;
                return;
            }
        }

        self.path.push(BgpPathAttribute {
            flags: BgpPathAttributeFlags {
                optional: true,
                transitiv: false,
                partial: false,
                extended_len: false,
            },
            attr: BgpPathAttributeKind::NextHop(BgpPathAttributeNextHop { hop: next_hop }),
        });
    }

    pub fn add_path_as(&mut self, as_num: AsNumber, maybe_origin: BgpPathAttributeOrigin) {
        if maybe_origin == BgpPathAttributeOrigin::Igp && !self.path.is_empty() {
            return;
        }
        let mut c = 0;

        for attr in &mut self.path {
            if let BgpPathAttributeKind::AsPath(ref mut as_attr) = attr.attr {
                if !as_attr.path.contains(&as_num) {
                    as_attr.path.insert(0, as_num);
                }
                c |= 0b1;
            }

            if let BgpPathAttributeKind::Origin(ref mut origin) = attr.attr {
                *origin = maybe_origin;
                c |= 0b01;
            }
        }

        // First path will be set
        if c & 0b01 == 0 {
            self.path.push(BgpPathAttribute {
                flags: BgpPathAttributeFlags {
                    optional: false,
                    transitiv: true,
                    partial: false,
                    extended_len: false,
                },
                attr: BgpPathAttributeKind::Origin(maybe_origin),
            });
        }

        if c & 0b1 == 0 {
            self.path.push(BgpPathAttribute {
                flags: BgpPathAttributeFlags {
                    optional: false,
                    transitiv: true,
                    partial: false,
                    extended_len: false,
                },
                attr: BgpPathAttributeKind::AsPath(BgpPathAttributeAsPath {
                    typ: BgpPathAttributeAsPathTyp::AsSequence,
                    path: vec![as_num],
                }),
            });
        }
    }
}
