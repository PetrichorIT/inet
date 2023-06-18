use std::{
    io::{Error, Result},
    net::{IpAddr, Ipv4Addr},
    ops::Deref,
};

use adj_in::{AdjIn, Peer, Route};
use adj_out::AdjRIBOut;
use des::time::SimTime;
use fxhash::{FxBuildHasher, FxHashMap};
use inet::{interface::InterfaceName, routing::add_routing_table, TcpListener};
use kernel::{DefaultBgpKernel, Kernel};
use loc_rib::LocRibWithKernel;
use peering::{BgpPeeringCfg, NeighborDeamon, NeighborHandle};
use pkt::{BgpUpdatePacket, Nlri};
use tokio::{
    spawn,
    sync::mpsc::{channel, Sender},
    task::JoinHandle,
};

use tracing::{Instrument, Level};
use types::AsNumber;

pub mod adj_in;
pub mod adj_out;
pub mod kernel;
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
    kernel: Option<Box<dyn Kernel>>,
}

pub struct DepolyedBgpDeamon {
    tx: Sender<BgpDeamonManagmentEvent>,
    task: JoinHandle<()>,
}

impl Deref for DepolyedBgpDeamon {
    type Target = Sender<BgpDeamonManagmentEvent>;
    fn deref(&self) -> &Self::Target {
        &self.tx
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BgpNodeInformation {
    pub addr: Ipv4Addr,
    pub iface: InterfaceName,
    pub as_num: AsNumber,
}

impl BgpNodeInformation {
    fn str(&self) -> String {
        format!("{}/{}", self.addr, self.as_num)
    }
}

#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum BgpDeamonManagmentEvent {
    StopPeering(Ipv4Addr),
    StartPeering(Ipv4Addr),
    Status,
}

#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum NeighborIngressEvent {
    ConnectionEstablished(BgpNodeInformation),
    ConnectionLost(BgpNodeInformation),

    Update(Ipv4Addr, BgpUpdatePacket),
    Notification(),
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
            kernel: None,
        }
    }

    pub fn kernel(mut self, kernel: impl Kernel + 'static) {
        self.kernel = Some(Box::new(kernel));
    }

    pub fn lan_iface(mut self, iface: &str) -> Self {
        self.local_iface = Some(InterfaceName::from(iface));
        self
    }

    pub fn add_neighbor(mut self, addr: Ipv4Addr, as_num: AsNumber, iface: &str) -> Self {
        self.neighbors.push(BgpNodeInformation {
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
    pub async fn deploy(mut self) -> Result<DepolyedBgpDeamon> {
        let table_id = add_routing_table()?;

        let (tx, mut rx) = channel(32);

        let mut neighbor_send_handles = FxHashMap::with_hasher(FxBuildHasher::default());
        let mut neighbor_tcp_handles = FxHashMap::with_hasher(FxBuildHasher::default());

        let host_info = BgpNodeInformation {
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
                up: true,
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

        let (mtx, mut mrx) = channel(8);
        let mtx2 = mtx.clone();

        let run_loop = spawn(async move {
            let _ = listener_handle;

            let mut adj_in = AdjIn::new();
            let mut loc_rib = LocRibWithKernel::new(
                table_id,
                self.kernel
                    .take()
                    .unwrap_or(Box::new(DefaultBgpKernel(host_info.clone()))),
            );
            let mut adj_out = AdjRIBOut::new(host_info);

            if !self.networks.is_empty() {
                let route = Route {
                    id: 0b1,
                    path: Vec::new(),
                    ts: SimTime::ZERO,
                    ucount: 0,
                };
                for network in self.networks {
                    loc_rib.add_dest(
                        network,
                        &route,
                        &Peer {
                            as_num: self.as_num,
                            next_hop: Ipv4Addr::UNSPECIFIED,
                            iface: self
                                .local_iface
                                .clone()
                                .unwrap_or(InterfaceName::from("invalid")),
                        },
                    );
                }
            }

            loop {
                let _ = &mtx2; // ensure mtx2 is moved into the func, and keept alive to prevent None loops
                use NeighborEgressEvent::*;
                use NeighborIngressEvent::*;

                if adj_in.is_dirty() {
                    let done = loc_rib.kernel_decision(&adj_in, &mut adj_out);

                    if done {
                        adj_in.unset_dirty();
                    }
                }

                let event = tokio::select! {
                    event = rx.recv() => event,
                    mng = mrx.recv() => {
                        use BgpDeamonManagmentEvent::*;
                        match mng.unwrap() {
                            StopPeering(peer) => {
                                let hndl = neighbor_send_handles
                                    .get_mut(&peer)
                                    .expect("neighbor not found");

                                hndl.up = false;
                                hndl.tx
                                    .send(Stop)
                                    .await
                                    .expect("failed to send");
                            },

                            StartPeering(peer) => {
                                let hndl = neighbor_send_handles
                                    .get_mut(&peer)
                                    .expect("neighbor not found");

                                hndl.up = false;
                                hndl.tx
                                    .send(Start)
                                    .await
                                    .expect("failed to send");
                            }

                            Status => {
                                let span = tracing::span!(tracing::Level::TRACE, "status").entered();
                                adj_in.status();
                                loc_rib.status();
                                // adj_out.status();

                                drop(span);
                            }
                        }
                        continue;
                    }
                    _ = adj_out.tick() => continue,
                };

                match event.unwrap() {
                    ConnectionEstablished(peer) => {
                        tracing::info!("new active neighbor {}", peer.str());
                        adj_in.register(&peer);
                        adj_out.register(&peer, &neighbor_send_handles);
                        loc_rib.psh_publish(&peer, &mut adj_out);
                    }
                    ConnectionLost(peer) => {
                        adj_in.unregister(&peer);
                        adj_out.unregister(&peer);

                        let done = loc_rib.kernel_decision(&adj_in, &mut adj_out);
                        assert!(done, "This could be a problem");

                        if done {
                            adj_in.unset_dirty()
                        }

                        let Some(hndl) =  neighbor_send_handles.get(&peer.addr) else {
                            todo!()
                        };

                        if hndl.up {
                            // should be restarted
                            hndl.tx.send(Start).await.expect("failed to send")
                        }
                    }
                    Update(peer, update) => adj_in.process(update, peer),
                    _ => todo!(),
                }
            }
        });

        Ok(DepolyedBgpDeamon {
            tx: mtx,
            task: run_loop,
        })
    }
}
