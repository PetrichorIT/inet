#![warn(clippy::pedantic)]
#![allow(
    async_fn_in_trait,
    clippy::missing_errors_doc,
    clippy::cast_possible_truncation
)]
//! The Routing Information Protocol (RIP)

use bytes_io::{FromBytes, ToBytes};
use des::time::{Duration, SimTime, sleep};
use fxhash::{FxBuildHasher, FxHashMap};
use std::{
    fmt::Debug,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    vec,
};

use inet::{
    Current, UdpSocket,
    interface::{IfId, InterfaceDef},
    ioctx,
    ipv4::{self, router::add_routing_entry},
    types::ip::{IpAddrLike, Ipv4Prefix, Ipv6AddrExt, Ipv6Prefix},
};

use inet::env::RoutingInformation;
use inet::env::RoutingPort;

mod ng;
mod pkt;

pub use self::ng::*;
pub use self::pkt::*;

/// Configuration of a single RIP router.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RipConfig {
    /// The maximum allowed age of any routing entry.
    pub entry_lifetime: Duration,
    /// The update interval for routing entries.
    pub entry_update_interval: Duration,
}

impl Default for RipConfig {
    fn default() -> Self {
        Self {
            entry_lifetime: Duration::from_secs(200),
            entry_update_interval: Duration::from_secs(60),
        }
    }
}

/// A routing deamon implementing RIP in a LAN.
///
/// Note that this deamon expects that no network interfaces
/// are defined yet.
#[derive(Debug, Clone)]
pub struct RipRoutingDeamon {
    cfg: RipConfig,
    addr: Ipv4Addr,
    mask: Ipv4Addr,

    neighbors: FxHashMap<Ipv4Addr, NeighborEntry>,
    vectors: FxHashMap<Ipv4Addr, DistanceVectorEntry>,
    next_timeout: SimTime,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct NeighborEntry {
    router: Ipv4Addr,
    mask: Ipv4Addr,
    iface: String,
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

impl RipRoutingDeamon {
    /// Creates a new routing deamin, that acts as the border router
    /// to a LAN in the given routing port.
    ///
    /// # Panics
    ///
    /// May panic if the interface cannot be added.
    #[must_use]
    pub fn lan_attached(
        raddr: Ipv4Addr,
        mask: Ipv4Addr,
        port: &RoutingPort,
        cfg: RipConfig,
    ) -> Self {
        ioctx()
            .add_interface(InterfaceDef::new("lan", port.clone().into()).ipv4_raw(raddr, mask))
            .unwrap();

        let ports = RoutingInformation::collect();
        let mut c = 0;
        for new_port in ports.ports {
            if *port != new_port {
                // test if gate chain has channel else invalid
                let mut chan = new_port.output.channel().is_some();

                for next in new_port
                    .output
                    .path_iter()
                    .expect("cannot use transit gate")
                {
                    chan |= next.channel.is_some();
                }

                if chan {
                    let iface = InterfaceDef::new(&format!("en{c}"), new_port.into())
                        .ipv4_raw(raddr, Ipv4Addr::UNSPECIFIED);
                    ioctx().add_interface(iface).unwrap();
                    c += 1;
                }
            }
        }

        Self {
            cfg,
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
        // tracing::info!(target: "inet/rip", "discovered new neighbor {router:?} ({mask:?}) on port {iface}");

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
            deadline: SimTime::now() + self.cfg.entry_lifetime,
            update_time: SimTime::now() + self.cfg.entry_update_interval,
        };
        if let Some(dv) = self.vectors.get_mut(&subnet) {
            *dv = v;
        } else {
            // tracing::trace!(target: "inet/rip", "new destination {:?}", subnet);
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

    /// Activates the deamon.
    ///
    /// This function will block forever, or until a critical error has occured.
    ///
    /// # Panics
    ///
    /// May panic.
    #[allow(clippy::too_many_lines)]
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
        let sock = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 520)).await.unwrap();
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
        sock.send_to(&req.write_to_vec().unwrap(), (Ipv4Addr::BROADCAST, 520))
            .await
            .unwrap();

        // (3) Loop routing
        loop {
            let mut buf = [0; 1024];
            let sleep_dur = (self
                .next_timeout
                .checked_duration_since(SimTime::now())
                .unwrap_or(Duration::ZERO))
            .min(self.cfg.entry_update_interval);

            let (n, from) = tokio::select! {
                result = sock.recv_from(&mut buf) => match result {
                    Ok(vv) => vv,
                    Err(e) => {
                        tracing::error!("socket recv error: {e}");
                        continue;
                    }
                },
                () = sleep(sleep_dur) => {
                    let mut updates = FxHashMap::with_hasher(FxBuildHasher::default());
                    for addr in self.vectors.keys().copied().collect::<Vec<_>>() {
                        let entry = self.vectors.get_mut(&addr).unwrap();

                        if SimTime::now() >= entry.deadline {
                            // Timeout
                            tracing::info!("Timeout for DV");
                        } else if SimTime::now() >= entry.update_time {
                            // request update
                            updates.entry(entry.gateway).or_insert(Vec::new()).push(RipEntry {
                                addr_fam: AF_INET,
                                target: entry.subnet,
                                mask: entry.mask,
                                next_hop: entry.gateway,
                                metric: entry.cost,
                            });
                            entry.update_time = SimTime::now() + self.cfg.entry_update_interval;
                        }
                    }

                    for (target, requests) in updates {
                        let pkts = RipPacket::packets(RipCommand::Request, &requests);
                        for pkt in pkts {
                            sock.send_to(&pkt.write_to_vec().unwrap(), (target, 520)).await.unwrap();
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
                let (incoming, new_neighbor) = if let Some(v) = self.neighbors.get(&v4) {
                    (v.iface.clone(), false)
                } else {
                    // current
                    let c = Current::fetch();
                    let info = ioctx().get_interface_by_ifid(c.ifid).unwrap().status();
                    (info.name.to_string(), true)
                };
                (v4, incoming, new_neighbor)
            } else {
                unreachable!()
            };

            let rip = RipPacket::peek_from(&buf[..n]).unwrap();
            let mut changes = Vec::new();

            match rip.command {
                RipCommand::Request => {
                    let mut rip = rip;
                    rip.command = RipCommand::Response;

                    if new_neighbor {
                        self.add_neighbor(raddr, rip.entries[0].mask, rport, &mut changes);
                    }

                    if rip.entries.len() == 1
                        && rip.entries[0].addr_fam == 0
                        && rip.entries[0].metric == 16
                    {
                        // request entire routing table
                        let dvs = self.full_dvs_for(raddr);
                        sock.send_to(&dvs.write_to_vec().unwrap(), from)
                            .await
                            .unwrap();
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
                        sock.send_to(&rip.write_to_vec().unwrap(), from)
                            .await
                            .unwrap();
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
                                    deadline: SimTime::now() + self.cfg.entry_lifetime,
                                    update_time: SimTime::now() + self.cfg.entry_update_interval,
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
                                route.deadline = SimTime::now() + self.cfg.entry_lifetime;
                                route.update_time = SimTime::now() + self.cfg.entry_update_interval;
                            }
                        } else {
                            if dv.target == local_subnet {
                                continue;
                            }
                            // tracing::trace!(target: "inet/rip", "new destination {:?} (info from {raddr})", dv.target);

                            self.vectors.insert(
                                dv.target,
                                DistanceVectorEntry {
                                    subnet: dv.target,
                                    mask: dv.mask,
                                    gateway: raddr,
                                    cost: dv.metric + 1,
                                    deadline: SimTime::now() + self.cfg.entry_lifetime,
                                    update_time: SimTime::now() + self.cfg.entry_update_interval,
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

            if changes.is_empty() {
                // log something
            } else {
                let publ = RipPacket::packets(RipCommand::Response, &changes);
                for pkt in publ {
                    for n in self.neighbors.keys() {
                        if new_neighbor && *n == raddr {
                            sock.send_to(&self.full_dvs_for(*n).write_to_vec().unwrap(), (*n, 520))
                                .await
                                .unwrap();
                        } else {
                            sock.send_to(&pkt.write_to_vec().unwrap(), (*n, 520))
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
            }
        }
    }
}

pub struct RipRouter<Addr: DistanceVectorAddrFamily> {
    cfg: RipConfig,
    addr: Addr,
    subnet: Addr::Prefix,

    neighbors: FxHashMap<Addr, DVNeighborEntry<Addr>>,
    vectors: FxHashMap<Addr::Prefix, DistanceVector<Addr>>,
    next_timeout: SimTime,
}

#[allow(unused)]
pub struct DVNeighborEntry<Addr: DistanceVectorAddrFamily> {
    iface: IfId,
    router: Addr,
    subnet: Addr::Prefix,
}

#[derive(Debug, Clone)]
pub struct DistanceVector<Addr: DistanceVectorAddrFamily> {
    prefix: Addr::Prefix,
    next_hop: Addr,
    metric: u32,
    deadline: SimTime,
    update_time: SimTime,
}

impl<AddrFam: DistanceVectorAddrFamily> RipRouter<AddrFam> {
    pub fn new(subnet: AddrFam::Prefix, addr: AddrFam, cfg: RipConfig) -> Self {
        Self {
            cfg,
            addr,
            subnet,
            neighbors: FxHashMap::default(),
            vectors: FxHashMap::default(),
            next_timeout: SimTime::MAX,
        }
    }

    fn add_neighbor(
        &mut self,
        router: AddrFam,
        subnet: AddrFam::Prefix,
        iface: IfId,
        changes: &mut Vec<DistanceVector<AddrFam>>,
    ) {
        self.neighbors.insert(
            router,
            DVNeighborEntry {
                iface,
                router,
                subnet,
            },
        );

        let dv = DistanceVector {
            prefix: subnet,
            next_hop: router,
            metric: 1,
            deadline: SimTime::now() + self.cfg.entry_lifetime,
            update_time: SimTime::now() + self.cfg.entry_update_interval,
        };

        self.vectors.insert(subnet, dv.clone());
        changes.push(dv);
    }

    /// Runs the routing deamon
    ///
    /// # Errors
    ///
    /// Returns an error if something goes wrong.
    pub async fn run(self) -> io::Result<()> {
        self.run_inner().await.inspect_err(|e| {
            tracing::error!("Error running RIP: {}", e);
        })
    }

    async fn run_inner(mut self) -> io::Result<()> {
        // (0) Initalize the DV table
        let self_dv = DistanceVector::<AddrFam> {
            prefix: self.subnet,
            next_hop: AddrFam::NULL,
            metric: 0,
            deadline: SimTime::MAX,
            update_time: SimTime::MAX,
        };
        self.vectors.insert(self.subnet, self_dv.clone());

        let sock = AddrFam::make_socket().await?;

        tracing::info!("Initializing RIP routing deamon");
        // FIXME
        let inital_req = AddrFam::make_full_dvs_req(self.addr, self.subnet);
        AddrFam::broadcast(&sock, inital_req).await?;

        loop {
            let mut buf = [0; 1500];
            let timeout_dur = (self
                .next_timeout
                .checked_duration_since(SimTime::now())
                .unwrap_or(Duration::ZERO))
            .min(self.cfg.entry_update_interval);

            let (n, from) = tokio::select! {
                result = sock.recv_from(&mut buf) => match result {
                    Ok(vv) => vv,
                    Err(e) => {
                        tracing::error!("socket recv error: {e}");
                        continue;
                    }
                },

                () = sleep(timeout_dur) => {
                    self.on_timeout(&sock).await?;
                    continue;
                }
            };

            let neighbor_addr = AddrFam::from_ip(from.ip());
            let (incoming_iface, is_new) = self.neighbors.get(&neighbor_addr).map_or_else(
                || {
                    let cur = Current::fetch();
                    (cur.ifid, true)
                },
                |neighbor| (neighbor.iface, false),
            );

            let packet = AddrFam::Packet::peek_from(&buf[..n])?;
            // tracing::info!("recv {packet:?} from {from}");

            let changes = self
                .on_incoming(
                    &sock,
                    packet,
                    (neighbor_addr, from.port()),
                    incoming_iface,
                    is_new,
                )
                .await?;

            if !changes.is_empty() {
                let pkts = AddrFam::dvs_to_packet(&changes, RipCommand::Response);

                for neighbor in self.neighbors.keys() {
                    if is_new && *neighbor == neighbor_addr {
                        // SEND FULL: FIXME
                        // FIXME: port shenans
                        AddrFam::send_to(&sock, &pkts, (*neighbor, from.port())).await?;
                    } else {
                        AddrFam::send_to(&sock, &pkts, (*neighbor, from.port())).await?;
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

    async fn on_timeout(&mut self, sock: &UdpSocket) -> io::Result<()> {
        let mut updates = FxHashMap::with_hasher(FxBuildHasher::default());
        for addr in self.vectors.keys().copied().collect::<Vec<_>>() {
            let entry = self.vectors.get_mut(&addr).unwrap();

            if SimTime::now() >= entry.deadline {
                // Timeout
                tracing::info!("Timeout for DV");
            } else if SimTime::now() >= entry.update_time {
                // request update
                updates
                    .entry(entry.next_hop)
                    .or_insert(Vec::new())
                    .push(entry.clone());
                entry.update_time = SimTime::now() + self.cfg.entry_update_interval;
            }
        }

        for (target, requests) in updates {
            let pkts = AddrFam::dvs_to_packet(&requests, RipCommand::Request);
            // FIXME: 0 port
            AddrFam::send_to(sock, &pkts, (target, 0)).await?;
        }

        let min = self
            .vectors
            .values()
            .map(|dv| dv.update_time)
            .min()
            .unwrap_or(SimTime::MAX);
        self.next_timeout = min.max(SimTime::now());

        Ok(())
    }

    async fn on_incoming(
        &mut self,
        sock: &UdpSocket,
        packet: AddrFam::Packet,
        from: (AddrFam, u16),
        incoming: IfId,
        is_new: bool,
    ) -> io::Result<Vec<DistanceVector<AddrFam>>> {
        let mut changes = Vec::new();

        match AddrFam::packet_into_command(&packet) {
            RipCommand::Request => {
                let dvs = AddrFam::packet_into_dvs(&packet, from.0);

                if is_new {
                    self.add_neighbor(from.0, dvs[0].prefix, incoming, &mut changes);
                }

                // FIXME: this needs a few more checks
                if dvs.len() == 1 && dvs[0].metric == 16 {
                    // (1a) Request complete table
                    let all = self
                        .vectors
                        .values()
                        .filter(|dv| dv.next_hop != from.0)
                        .cloned() // FIXME: this is expensive
                        .collect::<Vec<_>>();
                    let pkts = AddrFam::dvs_to_packet(&all, RipCommand::Response);
                    AddrFam::send_to(sock, &pkts, from).await?;
                } else {
                    // (1b) Specifc partial query
                    let mut dvs = dvs;

                    for dv in &mut dvs {
                        let Some(entry) = self.vectors.get(&dv.prefix) else {
                            dv.metric = 16;
                            dv.next_hop = AddrFam::NULL;
                            continue;
                        };

                        *dv = entry.clone();
                    }

                    let pkts = AddrFam::dvs_to_packet(&dvs, RipCommand::Response);
                    AddrFam::send_to(sock, &pkts, from).await?;
                }
            }
            RipCommand::Response => {
                for dv in AddrFam::packet_into_dvs(&packet, from.0) {
                    if is_new && dv.next_hop == AddrFam::NULL {
                        self.add_neighbor(from.0, dv.prefix, incoming, &mut changes);
                    }

                    if let Some(entry) = self.vectors.get_mut(&dv.prefix) {
                        // (2) Existing Entry
                        if entry.metric > dv.metric + 1 {
                            // (2a) Update entry with shorter route
                            *entry = dv;
                            entry.metric += 1;
                            entry.deadline = SimTime::now() + self.cfg.entry_lifetime;
                            entry.update_time = SimTime::now() + self.cfg.entry_update_interval;
                            AddrFam::add_routing_entry(entry, &incoming.to_string())?;
                            changes.push(entry.clone());
                        } else if entry.metric == dv.metric && entry.next_hop == dv.next_hop {
                            // (2b) Update entry with same route
                            entry.deadline = SimTime::now() + self.cfg.entry_lifetime;
                            entry.update_time = SimTime::now() + self.cfg.entry_update_interval;
                        }
                    } else {
                        // (3) New Entry
                        let mut entry = dv;
                        entry.metric += 1;
                        entry.deadline = SimTime::now() + self.cfg.entry_lifetime;
                        entry.update_time = SimTime::now() + self.cfg.entry_update_interval;

                        AddrFam::add_routing_entry(&entry, &incoming.to_string())?;
                        self.vectors.insert(entry.prefix, entry.clone());
                        changes.push(entry);
                    }
                }
            }
        }

        Ok(changes)
    }
}

pub trait DistanceVectorAddrFamily: IpAddrLike {
    type Packet: ToBytes<Error = std::io::Error> + FromBytes<Error = std::io::Error> + Debug;

    fn from_ip(ip: IpAddr) -> Self;

    async fn make_socket() -> io::Result<UdpSocket>;

    async fn broadcast(sock: &UdpSocket, pkt: Self::Packet) -> io::Result<()>;

    async fn send_to(sock: &UdpSocket, pkts: &[Self::Packet], to: (Self, u16)) -> io::Result<()>;

    fn add_routing_entry(dv: &DistanceVector<Self>, ifid: &str) -> io::Result<()>;

    fn packet_into_command(packet: &Self::Packet) -> RipCommand;

    fn packet_into_dvs(packet: &Self::Packet, src: Self) -> Vec<DistanceVector<Self>>;

    fn make_full_dvs_req(router: Self, subnet: Self::Prefix) -> Self::Packet;

    fn dvs_to_packet(dvs: &[DistanceVector<Self>], command: RipCommand) -> Vec<Self::Packet>;
}

impl DistanceVectorAddrFamily for Ipv4Addr {
    type Packet = RipPacket;

    fn from_ip(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(v4) => v4,
            IpAddr::V6(_) => unreachable!(),
        }
    }

    async fn make_socket() -> io::Result<UdpSocket> {
        let sock = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 520)).await?;
        sock.set_broadcast(true)?;
        Ok(sock)
    }

    async fn broadcast(sock: &UdpSocket, pkt: Self::Packet) -> io::Result<()> {
        sock.send_to(&pkt.write_to_bytes()?, (Ipv4Addr::BROADCAST, 520))
            .await?;
        Ok(())
    }

    async fn send_to(sock: &UdpSocket, pkts: &[Self::Packet], to: (Self, u16)) -> io::Result<()> {
        for pkt in pkts {
            sock.send_to(&pkt.write_to_bytes()?, to).await?;
        }
        Ok(())
    }

    fn add_routing_entry(dv: &DistanceVector<Self>, ifid: &str) -> io::Result<()> {
        ipv4::router::add_routing_entry(
            dv.prefix.addr(),
            dv.prefix.mask().into(),
            dv.next_hop,
            ifid,
        )
    }

    fn packet_into_command(packet: &Self::Packet) -> RipCommand {
        packet.command
    }

    fn packet_into_dvs(packet: &Self::Packet, _src: Self) -> Vec<DistanceVector<Self>> {
        packet
            .entries
            .iter()
            .map(|entry| DistanceVector {
                prefix: Ipv4Prefix::new(entry.target, u32::from(entry.mask).leading_ones() as u8),
                next_hop: entry.next_hop,
                metric: entry.metric,
                deadline: SimTime::ZERO,
                update_time: SimTime::ZERO,
            })
            .collect()
    }

    fn make_full_dvs_req(router: Self, subnet: Self::Prefix) -> Self::Packet {
        RipPacket {
            command: RipCommand::Request,
            entries: vec![RipEntry {
                addr_fam: 0,
                target: subnet.addr(),
                mask: subnet.mask().into(),
                next_hop: router,
                metric: 16,
            }],
        }
    }

    fn dvs_to_packet(mut dvs: &[DistanceVector<Self>], command: RipCommand) -> Vec<Self::Packet> {
        let mut r = Vec::with_capacity(dvs.len() / 25 + 1);
        while !dvs.is_empty() {
            let mut pkt = RipPacket {
                command,
                entries: Vec::with_capacity(dvs.len().min(25)),
            };

            for entry in &dvs[..25.min(dvs.len())] {
                pkt.entries.push(RipEntry {
                    addr_fam: AF_INET,
                    target: entry.prefix.addr(),
                    mask: entry.prefix.mask().into(),
                    next_hop: entry.next_hop,
                    metric: entry.metric,
                });
            }

            dvs = &dvs[pkt.entries.len()..];
            r.push(pkt);
        }
        r
    }
}

impl DistanceVectorAddrFamily for Ipv6Addr {
    type Packet = RipNgPacket;

    fn from_ip(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(_) => unreachable!(),
            IpAddr::V6(v6) => v6,
        }
    }

    async fn make_socket() -> io::Result<UdpSocket> {
        let sock = UdpSocket::bind((Ipv6Addr::UNSPECIFIED, 512)).await?;
        sock.set_broadcast(true)?;
        sock.join_multicast_v6(Ipv6Addr::MULTICAST_ALL_NODES, None)?;
        Ok(sock)
    }

    #[tracing::instrument(skip(sock, pkt))]
    async fn broadcast(sock: &UdpSocket, pkt: Self::Packet) -> io::Result<()> {
        // FIXME
        sock.send_to(&pkt.write_to_bytes()?, (Ipv6Addr::MULTICAST_ALL_NODES, 512))
            .await?;
        Ok(())
    }

    #[tracing::instrument(skip(sock, pkts, to))]
    async fn send_to(sock: &UdpSocket, pkts: &[Self::Packet], to: (Self, u16)) -> io::Result<()> {
        for pkt in pkts {
            sock.send_to(&pkt.write_to_bytes()?, to).await?;
        }
        Ok(())
    }

    fn add_routing_entry(dv: &DistanceVector<Self>, _ifid: &str) -> io::Result<()> {
        tracing::error!("add({} via {})", dv.prefix, dv.next_hop);
        Ok(())
        // ipv6::router::add_routing_entry(dv.prefix, dv.next_hop, Ipv6Addr::UNSPECIFIED)
    }

    fn packet_into_command(packet: &Self::Packet) -> RipCommand {
        packet.command
    }

    fn packet_into_dvs(packet: &Self::Packet, src: Self) -> Vec<DistanceVector<Self>> {
        packet
            .entries
            .iter()
            .map(|entry| DistanceVector {
                prefix: entry.prefix,
                next_hop: if entry.next_hop.is_unspecified() {
                    src
                } else {
                    entry.next_hop
                },
                metric: u32::from(entry.metrics),
                deadline: SimTime::ZERO,
                update_time: SimTime::ZERO,
            })
            .collect()
    }

    fn make_full_dvs_req(router: Self, _subnet: Self::Prefix) -> Self::Packet {
        RipNgPacket {
            command: RipCommand::Request,
            entries: vec![RipNgEntry {
                prefix: Ipv6Prefix::new(Ipv6Addr::UNSPECIFIED, 0),
                next_hop: router,
                tag: 0,
                metrics: 16,
            }],
        }
    }

    fn dvs_to_packet(mut dvs: &[DistanceVector<Self>], command: RipCommand) -> Vec<Self::Packet> {
        let mut r = Vec::with_capacity(dvs.len() / 25 + 1);
        while !dvs.is_empty() {
            let mut pkt = RipNgPacket {
                command,
                entries: Vec::with_capacity(dvs.len().min(25)),
            };

            for entry in &dvs[..25.min(dvs.len())] {
                pkt.entries.push(RipNgEntry {
                    prefix: entry.prefix,
                    next_hop: entry.next_hop,
                    tag: 0,
                    metrics: entry.metric as u8,
                });
            }

            dvs = &dvs[pkt.entries.len()..];
            r.push(pkt);
        }
        r
    }
}
