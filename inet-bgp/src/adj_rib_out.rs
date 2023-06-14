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
                dirty: false,
            },
        );
    }

    pub(super) fn publish_all(&mut self, entry: RIBEntry) {
        let keys = self.ribs.keys().copied().collect::<Vec<_>>();
        for key in keys {
            self.publish(entry.clone(), key);
        }
    }

    pub(super) fn publish(&mut self, mut entry: RIBEntry, peer: Ipv4Addr) {
        let Some(rib) = self.ribs.get_mut(&peer) else { todo!() };
        if entry.is_as_on_path(rib.info.as_num) {
            return;
        }

        entry.flag = false; // flag represents whether entry was allready advertised
        entry.add_path_as(
            self.host_info.as_num,
            if rib.info.as_num == self.host_info.as_num {
                BgpPathAttributeOrigin::Igp
            } else {
                BgpPathAttributeOrigin::Egp
            },
        );

        rib.rib.add(entry);
        rib.dirty = true;

        self.dirty = true;
    }

    pub(super) async fn tick(&mut self) {
        // tracing::info!("tick");

        if !self.dirty {
            return pending::<()>().await;
        }

        for (_, AdjOut { rib, dirty, tx, .. }) in &mut self.ribs {
            if !*dirty {
                continue;
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

    pub fn entries_mut(&mut self) -> &mut [RIBEntry] {
        &mut self.mapping
    }

    pub fn add(&mut self, entry: RIBEntry) {
        self.mapping.push(entry)
    }
}

impl RIBEntry {
    pub fn to_update(&self) -> BgpUpdatePacket {
        let mut path_attributes = self.path.clone();
        if !path_attributes
            .iter()
            .any(|a| matches!(a.attr, BgpPathAttributeKind::NextHop(_)))
        {
            path_attributes.push(BgpPathAttribute {
                flags: BgpPathAttributeFlags {
                    optional: false,
                    transitiv: false,
                    partial: false,
                    extended_len: false,
                },
                attr: BgpPathAttributeKind::NextHop(BgpPathAttributeNextHop { hop: self.next_hop }),
            })
        }
        BgpUpdatePacket {
            withdrawn_routes: Vec::new(),
            path_attributes,
            nlris: self.nlri.clone(),
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
