use std::{io::Result, net::Ipv4Addr};

use des::{time::SimTime, tokio::sync::mpsc::channel};
use inet::{TcpListener, TcpStream};
use peering::{BgpPeeringCfg, NeighborDeamon, NeighborHandle};
use pkt::BgpNrli;

use tracing::{Instrument, Level};
use types::AsNumber;

pub mod peering;
pub mod pkt;
pub mod types;

pub struct BgpDeamon {
    as_num: AsNumber,
    router_id: Ipv4Addr,
    networks: Vec<BgpNrli>,
    neighbors: Vec<BgpNodeInformation>,
}

#[derive(Debug, Clone)]
struct BgpNodeInformation {
    identifier: String,
    addr: Ipv4Addr,
    as_num: AsNumber,
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

#[derive(Debug)]
#[non_exhaustive]
enum NeighborIngressEvent {
    ConnectionEstablished(),
    Update(),
    Notification(),
    ConnectionLost(),
}

#[derive(Debug)]
#[non_exhaustive]
enum NeighborEgressEvent {
    Start,
    Stop,
}

impl BgpDeamon {
    pub fn new(as_num: AsNumber, router_id: Ipv4Addr) -> Self {
        Self {
            as_num,
            router_id,
            neighbors: Vec::new(),
            networks: Vec::new(),
        }
    }

    pub fn add_neighbor(mut self, addr: Ipv4Addr, as_num: AsNumber) -> Self {
        self.neighbors.push(BgpNodeInformation {
            identifier: String::new(),
            addr,
            as_num,
        });
        self
    }

    pub fn add_named_neighbor(
        mut self,
        identifer: impl AsRef<str>,
        addr: Ipv4Addr,
        as_num: AsNumber,
    ) -> Self {
        self.neighbors.push(BgpNodeInformation {
            identifier: identifer.as_ref().to_string(),
            addr,
            as_num,
        });
        self
    }

    #[tracing::instrument(name = "bgp", skip_all)]
    pub async fn deploy(self) -> Result<()> {
        let (tx, mut rx) = channel(32);

        let mut neighbor_send_handles = Vec::new();

        for neighbor in &self.neighbors {
            let (etx, erx) = channel(8);
            let (tcp_tx, tcp_rx) = channel(8);
            let deamon = NeighborDeamon {
                // state: NeighborDeamonState::Idle,
                peer_info: neighbor.clone(),
                host_info: BgpNodeInformation {
                    identifier: String::from("host"),
                    addr: self.router_id,
                    as_num: self.as_num,
                },
                cfg: BgpPeeringCfg::default(),

                last_keepalive_sent: SimTime::ZERO,
                last_keepalive_received: SimTime::ZERO,
                connect_retry_counter: 0,

                tx: tx.clone(),
                rx: erx,
                tcp_rx: tcp_rx,
            };

            let span = if !neighbor.identifier.is_empty() {
                tracing::span!(Level::TRACE, "bgp:peering", peer = neighbor.identifier)
            } else {
                tracing::span!(
                    Level::TRACE,
                    "bgp:peering",
                    peer = tracing::field::debug(neighbor.addr)
                )
            };

            let handle = NeighborHandle {
                tx: etx,
                tcp_tx: tcp_tx,
                task: tokio::spawn(deamon.deploy().instrument(span)),
            };
            handle.tx.send(NeighborEgressEvent::Start).await.unwrap();
            neighbor_send_handles.push(handle);
        }

        let listener = TcpListener::bind((Ipv4Addr::UNSPECIFIED, 179)).await?;

        loop {
            tokio::select! {
                stream = listener.accept() => {
                    let (stream, addr) = stream?;
                    // Find corresponding client for
                    // incoming connection
                    let Some((i, _neighbor)) = self.neighbors.iter().enumerate().find(|(_, n)| n.addr == addr.ip()) else {
                        continue;
                    };
                    tracing::trace!("new incoming connection from {:?}", addr);
                    let _ = neighbor_send_handles[i]
                        .tcp_tx
                        .send(stream)
                        .await.unwrap();
                }
                val = rx.recv() => {
                    dbg!(val);
                }
            };
        }
    }
}
