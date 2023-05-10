use des::time::SimTime;
use des::tokio::time::sleep;
use fxhash::{FxBuildHasher, FxHashMap};
use inet_types::routing::rip::RipCommand;
use inet_types::routing::rip::RipEntry;
use inet_types::routing::rip::RipPacket;
use inet_types::routing::rip::AF_INET;
use inet_types::FromBytestream;
use inet_types::IntoBytestream;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::time::Duration;

use crate::{
    interface::{add_interface, Interface},
    routing::add_routing_entry,
    UdpSocket,
};

use super::{update_routing_entry, RoutingPort};

const UPDATE_DELAY: Duration = Duration::from_secs(30);
const LIFETIME: Duration = Duration::from_secs(60);

#[derive(Debug, Clone)]
pub struct RoutingDeamon {
    addr: Ipv4Addr,
    mask: Ipv4Addr,
    lan_port: RoutingPort,

    neighbors: FxHashMap<Ipv4Addr, NeighborEntry>,
    vectors: FxHashMap<Ipv4Addr, DistanceVectorEntry>,
    iface_counter: usize,
    next_timeout: SimTime,
}

#[derive(Debug, Clone)]
pub struct NeighborEntry {
    router: Ipv4Addr,
    mask: Ipv4Addr,
    port: RoutingPort,
    iface: String,
}

impl NeighborEntry {
    pub fn new(router: Ipv4Addr, mask: Ipv4Addr, port: RoutingPort) -> Self {
        Self {
            router,
            mask,
            port,
            iface: String::new(),
        }
    }

    fn subnet(&self) -> Ipv4Addr {
        Ipv4Addr::from(u32::from(self.router) & u32::from(self.mask))
    }
}

#[derive(Debug, Clone)]
struct DistanceVectorEntry {
    subnet: Ipv4Addr,
    mask: Ipv4Addr,
    gateway: Ipv4Addr,
    cost: u32,
    deadline: SimTime,
    update_time: SimTime,
}

impl RoutingDeamon {
    pub fn new(raddr: Ipv4Addr, mask: Ipv4Addr, port: RoutingPort) -> Self {
        Self {
            addr: raddr,
            mask,
            lan_port: port,
            neighbors: FxHashMap::with_hasher(FxBuildHasher::default()),
            vectors: FxHashMap::with_hasher(FxBuildHasher::default()),
            iface_counter: 0,
            next_timeout: SimTime::MAX,
        }
    }

    pub fn declare_neighbor(&mut self, mut n: NeighborEntry) {
        if n.iface.is_empty() {
            add_interface(Interface::ethv4_named(
                format!("en{}", self.iface_counter),
                n.port.clone().into(),
                self.addr,
                Ipv4Addr::UNSPECIFIED,
            ))
            .unwrap();
            n.iface = format!("en{}", self.iface_counter);
            self.iface_counter += 1;
        }

        self.neighbors.insert(n.router, n);
    }

    fn full_dvs_for(&self, neighbor: Ipv4Addr) -> RipPacket {
        RipPacket {
            command: RipCommand::Response,
            entries: self
                .vectors
                .values()
                .filter(|d| d.gateway != neighbor)
                .map(|d| RipEntry {
                    addr_fam: AF_INET,
                    target: d.subnet,
                    mask: d.mask,
                    next_hop: d.gateway,
                    metric: d.cost,
                })
                .collect(),
        }
    }

    async fn pub_changes(&self, sock: &mut UdpSocket) {
        for n in self.neighbors.keys() {
            let dv = self.full_dvs_for(*n);
            sock.send_to(&dv.to_buffer().unwrap(), (*n, 520))
                .await
                .unwrap();
        }
    }

    pub async fn deploy(mut self) {
        add_interface(Interface::ethv4_named(
            "lan",
            self.lan_port.clone().into(),
            self.addr,
            self.mask,
        ))
        .unwrap();

        // self.vectors.insert(k, v)

        for neighbor in self.neighbors.values() {
            add_routing_entry(
                neighbor.subnet(),
                neighbor.mask,
                neighbor.router,
                &neighbor.iface,
            )
            .unwrap();
            self.vectors.insert(
                neighbor.subnet(),
                DistanceVectorEntry {
                    subnet: neighbor.subnet(),
                    mask: neighbor.mask,
                    gateway: neighbor.router,
                    cost: 1,
                    deadline: SimTime::MAX,
                    update_time: SimTime::MAX,
                },
            );
        }

        let mut sock = UdpSocket::bind("0.0.0.0:520").await.unwrap();
        self.pub_changes(&mut sock).await;

        loop {
            let mut buf = [0; 1024];
            let sleep_dur = (self.next_timeout - SimTime::now()).min(UPDATE_DELAY);

            let (n, from) = des::tokio::select! {
                result = sock.recv_from(&mut buf) => match result {
                    Ok(vv) => vv,
                    Err(e) => {
                        log::error!(target: "inet/rip", "socket recv error: {e}");
                        continue;
                    }
                },
                _ = sleep(sleep_dur) => {
                    let mut updates = FxHashMap::with_hasher(FxBuildHasher::default());
                    for addr in self.vectors.keys().cloned().collect::<Vec<_>>() {
                        let entry = self.vectors.get_mut(&addr).unwrap();
                        let rem = entry.deadline - SimTime::now();
                        if rem == Duration::ZERO {
                            // Timeout
                            log::info!("Timeout for DV");
                        } else {
                            // request update
                            updates.entry(entry.gateway).or_insert(Vec::new()).push(RipEntry {
                                addr_fam: AF_INET,
                                target: entry.subnet,
                                mask: entry.mask,
                                next_hop: entry.gateway,
                                metric: entry.cost,
                            });
                            entry.update_time = SimTime::now() + UPDATE_DELAY;
                        }
                    }

                    for (target, requests) in updates {
                        let pkts = RipPacket::packets(RipCommand::Request, &requests);
                        for pkt in pkts {
                            sock.send_to(&pkt.to_buffer().unwrap(), (target, 520)).await.unwrap();
                        }
                    }


                    let min = self
                        .vectors
                        .values()
                        .map(|dv| dv.update_time)
                        .min()
                        .unwrap_or(SimTime::MAX);
                    self.next_timeout = min.max(SimTime::now());
                    continue;
                },
            };

            let (raddr, rport) = if let IpAddr::V4(v4) = from.ip() {
                (v4, self.neighbors.get(&v4).unwrap().iface.clone())
            } else {
                unreachable!()
            };

            let rip = RipPacket::from_buffer(&buf[..n]).unwrap();
            let mut changes = Vec::new();

            match rip.command {
                RipCommand::Request => {
                    // TODO: special case
                    let mut rip = rip;
                    rip.command = RipCommand::Response;

                    for entry in &mut rip.entries {
                        // (0) Check local DVs
                        let Some(dv) = self.vectors.get(&entry.target) else {
                            entry.metric = 16;
                            entry.next_hop = Ipv4Addr::UNSPECIFIED;
                            continue;
                        };

                        *entry = RipEntry {
                            addr_fam: AF_INET,
                            target: dv.subnet,
                            mask: dv.mask,
                            next_hop: dv.gateway,
                            metric: dv.cost,
                        };
                    }

                    sock.send_to(&rip.to_buffer().unwrap(), from).await.unwrap();
                }
                RipCommand::Response => {
                    for dv in rip.entries {
                        if let Some(route) = self.vectors.get_mut(&dv.target) {
                            if route.cost > dv.metric + 1 {
                                *route = DistanceVectorEntry {
                                    subnet: dv.target,
                                    mask: dv.mask,
                                    gateway: raddr,
                                    cost: dv.metric + 1,
                                    deadline: SimTime::now() + LIFETIME,
                                    update_time: SimTime::now() + UPDATE_DELAY,
                                };
                                update_routing_entry(dv.target, dv.mask, raddr, &rport).unwrap();
                                changes.push(RipEntry {
                                    addr_fam: AF_INET,
                                    target: dv.target,
                                    mask: dv.mask,
                                    next_hop: raddr,
                                    metric: dv.metric + 1,
                                });
                            } else if route.cost == dv.metric + 1 && route.gateway == dv.next_hop {
                                // Update
                                route.deadline = SimTime::now() + LIFETIME;
                                route.update_time = SimTime::now() + UPDATE_DELAY;
                            }
                        } else {
                            self.vectors.insert(
                                dv.target,
                                DistanceVectorEntry {
                                    subnet: dv.target,
                                    mask: dv.mask,
                                    gateway: raddr,
                                    cost: dv.metric + 1,
                                    deadline: SimTime::now() + LIFETIME,
                                    update_time: SimTime::now() + UPDATE_DELAY,
                                },
                            );
                            add_routing_entry(dv.target, dv.mask, raddr, &rport).unwrap();
                            changes.push(RipEntry {
                                addr_fam: AF_INET,
                                target: dv.target,
                                mask: dv.mask,
                                next_hop: raddr,
                                metric: dv.metric + 1,
                            });
                        }
                    }

                    if !changes.is_empty() {
                        let publ = RipPacket::packets(RipCommand::Response, &changes);
                        for pkt in publ {
                            for n in self.neighbors.keys() {
                                sock.send_to(&pkt.to_buffer().unwrap(), (*n, 520))
                                    .await
                                    .unwrap();
                            }
                        }

                        let min = self
                            .vectors
                            .values()
                            .map(|dv| dv.update_time)
                            .min()
                            .unwrap_or(SimTime::MAX);
                        self.next_timeout = min.max(SimTime::now());
                    }
                }
            }
        }
    }
}
