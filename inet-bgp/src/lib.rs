use std::{
    io::{Error, Result},
    net::{IpAddr, Ipv4Addr},
};

use adj_in::{AdjIn, Peer, Route};
use adj_rib_out::AdjRIBOut;
use des::time::SimTime;
use fxhash::{FxBuildHasher, FxHashMap};
use inet::{interface::InterfaceName, routing::add_routing_table, TcpListener};
use loc_rib::LocRib;
use peering::{BgpPeeringCfg, NeighborDeamon, NeighborHandle};
use pkt::{BgpUpdatePacket, Nlri};
use tokio::sync::mpsc::channel;

use tracing::{Instrument, Level};
use types::AsNumber;

pub mod adj_in;
pub mod adj_rib_out;
pub mod loc_rib;
pub mod peering;
pub mod pkt;
pub mod types;

pub struct BgpDeamon {
    as_num: AsNumber,
    router_id: Ipv4Addr,
    local_iface: Option<InterfaceName>,
    networks: Vec<Nlri>,
    neighbors: Vec<BgpNodeInformation>,
    default_cfg: BgpPeeringCfg,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BgpNodeInformation {
    pub identifier: String,
    pub addr: Ipv4Addr,
    pub iface: InterfaceName,
    pub as_num: AsNumber,
}

impl BgpNodeInformation {
    fn str(&self) -> String {
        if self.identifier.is_empty() {
            format!("{}/{}", self.addr, self.as_num)
        } else {
            self.identifier.clone()
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum NeighborIngressEvent {
    ConnectionEstablished(BgpNodeInformation),
    Update(Ipv4Addr, BgpUpdatePacket),
    Notification(),
    ConnectionLost(),
}

#[derive(Debug)]
#[non_exhaustive]
pub enum NeighborEgressEvent {
    Start,
    Stop,
    Advertise(BgpUpdatePacket),
}

impl BgpDeamon {
    pub fn new(as_num: AsNumber, router_id: Ipv4Addr) -> Self {
        Self {
            as_num,
            router_id,
            local_iface: None,
            neighbors: Vec::new(),
            networks: Vec::new(),
            default_cfg: BgpPeeringCfg::default(),
        }
    }

    pub fn add_neighbor(mut self, addr: Ipv4Addr, as_num: AsNumber, iface: &str) -> Self {
        self.neighbors.push(BgpNodeInformation {
            identifier: String::new(),
            addr,
            as_num,
            iface: InterfaceName::from(iface),
        });
        self
    }

    pub fn add_nlri(mut self, nlri: Nlri) -> Self {
        self.networks.push(nlri);
        self
    }

    #[tracing::instrument(name = "bgp", skip_all)]
    pub async fn deploy(self) -> Result<()> {
        let table_id = add_routing_table()?;

        let (tx, mut rx) = channel(32);

        let mut neighbor_send_handles = FxHashMap::with_hasher(FxBuildHasher::default());
        let mut neighbor_tcp_handles = FxHashMap::with_hasher(FxBuildHasher::default());

        let host_info = BgpNodeInformation {
            identifier: String::from("host"),
            addr: self.router_id,
            as_num: self.as_num,
            iface: self
                .local_iface
                .clone()
                .unwrap_or(InterfaceName::from("invalid")),
        };

        for neighbor in &self.neighbors {
            let (etx, erx) = channel(8);
            let (tcp_tx, tcp_rx) = channel(8);
            let mut host_info = host_info.clone();
            host_info.iface = neighbor.iface.clone();

            let deamon = NeighborDeamon::new(
                host_info,
                neighbor.clone(),
                tx.clone(),
                erx,
                tcp_rx,
                self.default_cfg.clone(),
            );

            let span = tracing::span!(
                Level::TRACE,
                "bgp:peering",
                peer = tracing::field::debug(neighbor.addr)
            );

            let handle = NeighborHandle {
                tx: etx,
                task: tokio::spawn(deamon.deploy().instrument(span)),
            };
            handle.tx.send(NeighborEgressEvent::Start).await.unwrap();
            neighbor_send_handles.insert(neighbor.addr, handle);
            neighbor_tcp_handles.insert(IpAddr::V4(neighbor.addr), tcp_tx);
        }

        let span = tracing::span!(Level::TRACE, "bgp listener");
        let listener_handle = tokio::spawn(
            async move {
                let listener = TcpListener::bind((Ipv4Addr::UNSPECIFIED, 179)).await?;
                while let Ok((stream, from)) = listener.accept().await {
                    if let Some(neighbor) = neighbor_tcp_handles.get(&from.ip()) {
                        tracing::debug!("incoming connection ({:?} -> local:179)", from);
                        neighbor.send(stream).await.unwrap();
                    } else {
                        tracing::warn!("incoming connection not directed at any bgp port")
                    }
                }
                Ok::<_, Error>(())
            }
            .instrument(span),
        );

        let _ = listener_handle;

        let mut adj_rib_in = AdjIn::new();
        let mut loc_rib = LocRib::new(table_id);
        let mut adj_rib_out = AdjRIBOut::new(host_info);

        if !self.networks.is_empty() {
            let route = Route {
                id: 0b1,
                peer: Peer {
                    as_num: self.as_num,
                    next_hop: Ipv4Addr::UNSPECIFIED,
                    iface: self.local_iface.unwrap_or(InterfaceName::from("invalid")),
                },
                path: Vec::new(),
                ts: SimTime::ZERO,
                new_route: false,
            };
            for network in self.networks {
                loc_rib.add_dest(network, &route);
            }
        }

        loop {
            use NeighborEgressEvent::*;
            use NeighborIngressEvent::*;

            if adj_rib_in.is_dirty() {
                for (dest, path) in adj_rib_in.paths() {
                    if !path.new_route {
                        continue;
                    }

                    if loc_rib.lookup(dest).is_none() {
                        loc_rib.add_dest(dest, path);
                        loc_rib.advertise_dest(dest, &mut adj_rib_out);
                        tracing::info!("new route to destination {dest:?}");
                    }
                }

                adj_rib_in.unset_dirty();
            }

            let event = tokio::select! {
                event = rx.recv() => event,
                _ = adj_rib_out.tick() => continue,
            };

            match event.unwrap() {
                ConnectionEstablished(peer) => {
                    tracing::info!("new active neighbor {}", peer.str());
                    adj_rib_in.register(&peer);
                    adj_rib_out.register(&peer, &neighbor_send_handles);
                    loc_rib.psh_publish(&peer, &mut adj_rib_out);
                }
                Update(peer, update) => adj_rib_in.process(update, peer),
                _ => todo!(),
            }
        }
    }
}
