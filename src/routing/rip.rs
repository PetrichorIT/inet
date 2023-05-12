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

use crate::IOContext;
use crate::{
    interface::{add_interface, Interface},
    routing::add_routing_entry,
    UdpSocket,
};

use super::RoutingInformation;
use super::RoutingPort;

const UPDATE_DELAY: Duration = Duration::from_secs(60);
const LIFETIME: Duration = Duration::from_secs(200);

#[derive(Debug, Clone)]
pub struct RoutingDeamon {
    addr: Ipv4Addr,
    mask: Ipv4Addr,

    neighbors: FxHashMap<Ipv4Addr, NeighborEntry>,
    vectors: FxHashMap<Ipv4Addr, DistanceVectorEntry>,
    next_timeout: SimTime,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct NeighborEntry {
    router: Ipv4Addr,
    mask: Ipv4Addr,
    iface: String,
}

impl NeighborEntry {
    pub fn new(router: Ipv4Addr, mask: Ipv4Addr, iface: String) -> Self {
        Self {
            router,
            mask,
            iface,
        }
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
        add_interface(Interface::ethv4_named(
            "lan",
            port.clone().into(),
            raddr,
            mask,
        ))
        .unwrap();

        let ports = RoutingInformation::collect();
        let mut c = 0;
        for new_port in ports.ports {
            if port != new_port {
                // test if gate chain has channel else invalid
                let mut chan = new_port.output.channel().is_some();
                let mut cur = new_port.output.clone();
                while let Some(next) = cur.next_gate() {
                    cur = next;
                    chan |= cur.channel().is_some();
                }

                if chan {
                    let iface = Interface::ethv4_named(
                        format!("en{c}"),
                        new_port.into(),
                        raddr,
                        Ipv4Addr::UNSPECIFIED,
                    );
                    add_interface(iface).unwrap();
                    c += 1;
                }
            }
        }

        Self {
            addr: raddr,
            mask,
            neighbors: FxHashMap::with_hasher(FxBuildHasher::default()),
            vectors: FxHashMap::with_hasher(FxBuildHasher::default()),
            next_timeout: SimTime::MAX,
        }
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

    fn add_neighbor(
        &mut self,
        router: Ipv4Addr,
        mask: Ipv4Addr,
        iface: String,
        changes: &mut Vec<RipEntry>,
    ) {
        // log::info!(target: "inet/rip", "discovered new neighbor {router:?} ({mask:?}) on port {iface}");

        let subnet = Ipv4Addr::from(u32::from(router) & u32::from(mask));

        add_routing_entry(subnet, mask, router, &iface).unwrap();
        self.neighbors.insert(
            router,
            NeighborEntry {
                router,
                mask,
                iface,
            },
        );

        let v = DistanceVectorEntry {
            subnet,
            mask,
            gateway: router,
            cost: 1,
            deadline: SimTime::now() + LIFETIME,
            update_time: SimTime::now() + UPDATE_DELAY,
        };
        if let Some(dv) = self.vectors.get_mut(&subnet) {
            *dv = v;
        } else {
            // log::trace!(target: "inet/rip", "new destination {:?}", subnet);
            self.vectors.insert(subnet, v);
        }

        changes.push(RipEntry {
            addr_fam: AF_INET,
            target: subnet,
            mask,
            next_hop: router,
            metric: 1,
        });
    }

    pub async fn deploy(mut self) {
        // (0) Initalize the DVs with just self as a target
        let local_subnet = Ipv4Addr::from(u32::from(self.addr) & u32::from(self.mask));
        self.vectors.insert(
            local_subnet,
            DistanceVectorEntry {
                subnet: local_subnet,
                mask: self.mask,
                gateway: Ipv4Addr::UNSPECIFIED,
                cost: 0,
                deadline: SimTime::MAX,
                update_time: SimTime::MAX,
            },
        );

        // (1) Open a socket and publish the self as a contensant
        let sock = UdpSocket::bind("0.0.0.0:520").await.unwrap();
        sock.set_broadcast(true).unwrap();

        // (2) Request updates from all ajacent routers.
        let req = RipPacket {
            command: RipCommand::Request,
            entries: vec![RipEntry {
                addr_fam: 0,
                target: Ipv4Addr::from(u32::from(self.addr) & u32::from(self.mask)),
                mask: self.mask,
                next_hop: self.addr,
                metric: 16,
            }],
        };
        sock.send_to(&req.to_buffer().unwrap(), (Ipv4Addr::BROADCAST, 520))
            .await
            .unwrap();

        // (3) Loop routing
        loop {
            let mut buf = [0; 1024];
            let sleep_dur = (self
                .next_timeout
                .checked_duration_since(SimTime::now())
                .unwrap_or(Duration::ZERO))
            .min(UPDATE_DELAY);

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

                        if SimTime::now() >= entry.deadline {
                            // Timeout
                            log::info!("Timeout for DV");
                        } else if SimTime::now() >= entry.update_time {
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

            let (raddr, rport, new_neighbor) = if let IpAddr::V4(v4) = from.ip() {
                let (incoming, new_neighbor) = match self.neighbors.get(&v4) {
                    Some(v) => (v.iface.clone(), false),
                    None => IOContext::with_current(|ctx| {
                        let iface = ctx.ifaces.get(&ctx.current.ifid).unwrap();
                        (iface.name.name.clone(), true)
                    }),
                };
                (v4, incoming, new_neighbor)
            } else {
                unreachable!()
            };

            let rip = RipPacket::from_buffer(&buf[..n]).unwrap();
            let mut changes = Vec::new();

            match rip.command {
                RipCommand::Request => {
                    let mut rip = rip;
                    rip.command = RipCommand::Response;

                    if new_neighbor {
                        self.add_neighbor(raddr, rip.entries[0].mask, rport, &mut changes)
                    }

                    if rip.entries.len() == 1
                        && rip.entries[0].addr_fam == 0
                        && rip.entries[0].metric == 16
                    {
                        // request entire routing table
                        let dvs = self.full_dvs_for(raddr);
                        sock.send_to(&dvs.to_buffer().unwrap(), from).await.unwrap();
                    } else {
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
                }
                RipCommand::Response => {
                    for dv in rip.entries {
                        if new_neighbor
                            && Ipv4Addr::from(u32::from(raddr) & u32::from(dv.mask)) == dv.target
                        {
                            self.add_neighbor(raddr, dv.mask, rport.clone(), &mut changes);
                        }

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
                                add_routing_entry(dv.target, dv.mask, raddr, &rport).unwrap();
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
                            if dv.target == local_subnet {
                                continue;
                            }
                            // log::trace!(target: "inet/rip", "new destination {:?} (info from {raddr})", dv.target);

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
                }
            }

            if !changes.is_empty() {
                // log::trace!(
                //     "{} changes to be published to {} neighbors",
                //     changes.len(),
                //     self.neighbors.len()
                // );
                let publ = RipPacket::packets(RipCommand::Response, &changes);
                for pkt in publ {
                    for n in self.neighbors.keys() {
                        if new_neighbor && *n == raddr {
                            sock.send_to(&self.full_dvs_for(*n).to_buffer().unwrap(), (*n, 520))
                                .await
                                .unwrap();
                        } else {
                            sock.send_to(&pkt.to_buffer().unwrap(), (*n, 520))
                                .await
                                .unwrap();
                        }
                    }
                }

                let min = self
                    .vectors
                    .values()
                    .map(|dv| dv.update_time)
                    .min()
                    .unwrap_or(SimTime::MAX);
                self.next_timeout = min.max(SimTime::now());
            } else {
                // log::trace!("no changes");
            }
        }
    }
}
