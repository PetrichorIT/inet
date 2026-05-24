#![warn(clippy::pedantic)]
#![allow(clippy::cast_possible_truncation)]

use std::{
    fmt::Debug,
    fs::File,
    future::pending,
    io,
    net::{IpAddr, Ipv6Addr},
    ops::Deref,
    sync::Arc,
    time::Duration,
};

use bytes_io::{FromBytes, ToBytes};
use des::{
    module::current,
    random,
    time::{Interval, SimTime, interval},
};
use inet::{
    env::RoutingPort,
    interface::{InterfaceDef, InterfaceHandle, NetworkDevice},
    ioctx,
    ipv6::{router, socket::RawV6Socket},
    types::ip::{Ipv6AddrExt, Ipv6AddrScope, Ipv6Packet},
};
use inet_pcap::pcap;
use petgraph::Graph;
use tokio::{sync::Mutex, task::futures};

use crate::packet::{
    AreaId, Ipv6Prefix, LasTypeFlags, Lsa, LsaDetachedHeader, LsaHeader, NetworkLsa,
    OspfDatabaseDescriptionOptions, OspfDatabaseDescriptionPacket, OspfHelloPacket, OspfOptions,
    OspfPacket, OspfPacketType, PROTO_OSPF, RouterId, RouterLsa, RouterLsaFlags,
};

pub mod packet;
mod timer;

//
// Data structures
//
// Area
// Backbone area structure
// Virtual links
// List of external ndoes
// List of AS-External LSA
// Routing table
//
//

pub struct Deamon {}

#[derive(Debug)]
pub struct Area {
    pub db: Arc<LinkStateDatabase>,

    pub ranges: Vec<Ipv6Prefix>,
    pub interfaces: Vec<InterfaceHandle>,
    // pub summary_lsas: Vec<Summay>,
    pub tree: Graph<RouterId, ()>,
    pub transit_capable: bool,
    pub external_routing_capability: bool,
    pub stub_default_cost: u32,
}

#[derive(Default)]
pub struct LinkStateDatabase {
    pub router_id: RouterId,
    pub area_id: AreaId,
    pub router_lsas: Mutex<Vec<(LsaHeader, RouterLsa)>>,
    pub network_lsas: Mutex<Vec<NetworkLsa>>,
}

impl Area {
    pub fn new(router_id: RouterId, area_id: AreaId) -> Self {
        Self {
            db: Arc::new(LinkStateDatabase {
                router_id,
                area_id,
                ..Default::default()
            }),
            ranges: Vec::new(),
            interfaces: Vec::new(),
            tree: Graph::new(),
            transit_capable: false,
            external_routing_capability: false,
            stub_default_cost: 0,
        }
    }
}

impl LinkStateDatabase {
    pub async fn add_router_lsa(&self, lsa: RouterLsa) {
        let mut router_lsas = self.router_lsas.lock().await;
        router_lsas.push((
            LsaHeader {
                ls_age: Duration::from_secs(0b1000_0000_0000_0000),
                link_state_id: 0,
                advertising_router: self.router_id.into(),
                ls_seq_no: 0,
                flags: LasTypeFlags::S1,
            },
            lsa,
        ));
    }

    pub async fn db_description(&self) -> Vec<LsaDetachedHeader> {
        self.router_lsas
            .lock()
            .await
            .iter()
            .map(|(header, content)| {
                LsaDetachedHeader::from(Lsa {
                    header: header.clone(),
                    content: packet::LsaKind::RouterLsa(content.clone()),
                })
            })
            .collect()
    }
}

impl Deref for Area {
    type Target = LinkStateDatabase;
    fn deref(&self) -> &Self::Target {
        &self.db
    }
}

impl Debug for LinkStateDatabase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DB").finish()
    }
}

#[derive(Debug)]
pub struct Interface {
    pub db: Arc<LinkStateDatabase>,
    pub socket: RawV6Socket,
    pub instance_id: u8,

    pub typ: InterfaceType,
    pub state: InterfaceState,
    pub addr: Ipv6Addr, // eq to fe80 for interface (derive from handle)

    pub hello_interval: Duration,
    pub router_dead_interval: Duration,
    pub inf_trans_delay: Duration,
    pub router_priority: u8,
    pub interface_output_cost: u32,
    pub rxmt_interval: Duration,

    pub designated_router: Option<RouterId>,
    pub backup_designated_router: Option<RouterId>,

    // Timers
    pub hello_timer: (),
    pub wait_timer: (),
    pub neighbors: Vec<Neighbor>,
}

#[derive(Debug, Clone)]
pub enum InterfaceType {
    PointToPoint(InterfaceHandle),
    Broadcast(InterfaceHandle),
    NBMA,
    PointToMultiPoint,
    VirtualLink,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InterfaceState {
    Down,
    Lookback,
    Waiting,
    Point2Point,
    DesignatedRouter,
    BackupDesignatedRouter,
    OtherDesignatedRouter,
}

impl Area {
    pub fn new_interface(&mut self, iface: InterfaceHandle) -> io::Result<Interface> {
        let addr = iface
            .status()
            .addrs
            .addrs()
            .find_map(|a| match a {
                IpAddr::V6(a6) => (a6.scope() == Ipv6AddrScope::UnicastLinkLocal).then_some(a6),
                _ => None,
            })
            .unwrap();

        Ok(Interface {
            db: self.db.clone(),
            socket: {
                let mut socket = RawV6Socket::new(PROTO_OSPF).unwrap();
                socket.bind(addr)?;
                socket.join_multicast(Ipv6Addr::MULTICAST_ALL_ROUTERS)?;
                socket
            },
            instance_id: 0,

            typ: InterfaceType::PointToPoint(iface),
            state: InterfaceState::Down,
            addr,

            hello_interval: Duration::from_secs(40),
            router_dead_interval: Duration::from_secs(20),
            inf_trans_delay: Duration::from_secs(10),
            router_priority: 0,
            interface_output_cost: 0,
            rxmt_interval: Duration::from_secs(10),

            designated_router: None,
            backup_designated_router: None,
            hello_timer: (),
            wait_timer: (),
            neighbors: Vec::new(),
        })
    }
}

impl Interface {
    pub fn wrap(&self, content: OspfPacketType) -> OspfPacket {
        OspfPacket {
            router_id: self.router_id,
            area_id: self.area_id,
            instance_id: 0,
            content,
        }
    }

    pub fn hello(&self) -> OspfPacket {
        let hello = OspfHelloPacket {
            interface_id: 0,
            router_priority: 0,
            options: OspfOptions::empty(),
            hello_interval: self.hello_interval,
            router_dead_interval: self.router_dead_interval,
            designated_router_id: self.designated_router,
            backup_router_id: self.backup_designated_router,
            neighbor_ids: self.neighbors.iter().map(|v| v.id).collect(),
        };
        self.wrap(OspfPacketType::Hello(hello))
    }

    pub async fn send_hello(&mut self) {
        tracing::debug!("sending hello");
        let hello = self.hello();
        if let Err(e) = self
            .socket
            .send_to(
                &hello.write_to_bytes().unwrap(),
                Ipv6Addr::MULTICAST_ALL_ROUTERS,
            )
            .await
        {
            tracing::error!("{:?}", e);
        }
    }

    pub async fn poll_rmtx_timers(&mut self) {
        for neighbor in self.neighbors.iter_mut() {
            neighbor.rmtx_timer.tick().await;
        }
        pending::<()>().await
    }

    pub async fn on_hello(&mut self, ip: &Ipv6Packet, pkt: &OspfPacket, hello: &OspfHelloPacket) {
        if self.neighbors.iter().all(|n| n.id != pkt.router_id) {
            self.send_hello().await;

            let neighbor = Neighbor {
                db: self.db.clone(),
                router_id: self.router_id,
                area_id: self.area_id,
                instance_id: self.instance_id,

                id: pkt.router_id,
                priority: hello.router_priority,
                n_addr: ip.src,
                options: hello.options,
                n_designated_router: hello.designated_router_id,
                n_designated_router_backup: hello.backup_router_id,
                state: NeighborState::Init,
                inactivity_timer: (),
                is_master: false,
                dd_seqno: 0,
                last_received_dd: None,
                retransmit_list: Vec::new(),
                rmtx_timer: interval(Duration::from_secs(4)),
                summary_list: Vec::new(),
                request_list: Vec::new(),
                summary_list_free_len: 0,
            };

            tracing::trace!("new neighbor {neighbor:?}");
            self.neighbors.push(neighbor);
        }
    }
}

impl Deref for Interface {
    type Target = LinkStateDatabase;
    fn deref(&self) -> &Self::Target {
        &self.db
    }
}

#[derive(Debug)]
pub struct Neighbor {
    pub db: Arc<LinkStateDatabase>,

    pub router_id: RouterId,
    pub area_id: AreaId,
    pub instance_id: u8,

    pub id: RouterId,
    pub priority: u8,
    pub n_addr: Ipv6Addr,
    pub options: OspfOptions,
    pub n_designated_router: Option<RouterId>,
    pub n_designated_router_backup: Option<RouterId>,

    pub state: NeighborState,
    pub inactivity_timer: (),
    pub is_master: bool,
    pub dd_seqno: u32,
    pub rmtx_timer: Interval,
    pub last_received_dd: Option<OspfDatabaseDescriptionPacket>,

    pub retransmit_list: Vec<Lsa>,
    pub summary_list: Vec<LsaDetachedHeader>,
    pub summary_list_free_len: usize,
    pub request_list: Vec<Lsa>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NeighborState {
    Down,
    Attempt,
    Init,
    ExStart,
    TwoWay,
    Exchange,
    Loading,
    Full,
}

impl Neighbor {
    pub async fn on_two_way(&mut self, socket: &mut RawV6Socket) -> io::Result<()> {
        self.state = NeighborState::ExStart;
        self.dd_seqno = random();
        self.is_master = true;

        tracing::info!("EX start ({}, seq {})", self.id, self.dd_seqno);

        let addr = self.n_addr;
        let next = self.dd_next();
        socket
            .send_to(
                &self
                    .wrap(OspfPacketType::DatabaseDescription(next))
                    .write_to_bytes()?,
                addr,
            )
            .await?;

        self.summary_list = self.db.db_description().await;

        // share the contents of the database i (MS) + (M) packets

        Ok(())
    }

    pub fn dd_next(&mut self) -> OspfDatabaseDescriptionPacket {
        if let NeighborState::ExStart = self.state {
            return OspfDatabaseDescriptionPacket {
                interface_mtu: 1500, // TODO: set correctly / 0 for virtual links
                options: OspfOptions::empty(),
                dd_seqno: self.dd_seqno,
                db_options: OspfDatabaseDescriptionOptions::INIT
                    | OspfDatabaseDescriptionOptions::MORE
                    | OspfDatabaseDescriptionOptions::MASTER,
                lsas: Vec::new(),
            };
        }

        if let NeighborState::Exchange = self.state {
            let mut db_options = OspfDatabaseDescriptionOptions::empty();
            if self.is_master {
                db_options |= OspfDatabaseDescriptionOptions::MASTER;
            }
            if !self.summary_list.is_empty() {
                db_options |= OspfDatabaseDescriptionOptions::MORE;
            }

            let mut pkt = OspfDatabaseDescriptionPacket {
                interface_mtu: 1500, // TODO: set correctly / 0 for virtual links
                options: OspfOptions::empty(),
                dd_seqno: self.dd_seqno,
                db_options,
                lsas: Vec::new(),
            };

            if let NeighborState::Exchange = self.state {
                // let mut rem = 1500 - 120;
                pkt.lsas = self.summary_list.clone();
                self.summary_list_free_len = pkt.lsas.len();
            }

            return pkt;
        }

        if let NeighborState::Loading | NeighborState::Full = self.state {
            if self.is_master {
                return OspfDatabaseDescriptionPacket {
                    interface_mtu: 1500, // TODO: set correctly / 0 for virtual links
                    options: OspfOptions::empty(),
                    dd_seqno: self.dd_seqno,
                    db_options: OspfDatabaseDescriptionOptions::MASTER,
                    lsas: Vec::new(),
                };
            } else {
                return OspfDatabaseDescriptionPacket {
                    interface_mtu: 1500, // TODO: set correctly / 0 for virtual links
                    options: OspfOptions::empty(),
                    dd_seqno: self.dd_seqno,
                    db_options: OspfDatabaseDescriptionOptions::empty(),
                    lsas: Vec::new(),
                };
            }
        }

        unreachable!()
    }

    pub async fn on_dd(
        &mut self,
        pkt: &OspfPacket,
        dd: &OspfDatabaseDescriptionPacket,
        socket: &mut RawV6Socket,
    ) -> io::Result<()> {
        type O = OspfDatabaseDescriptionOptions;
        // (Validate) TODO

        // (1) Save the last DD packet info
        let is_dup = self.last_received_dd.as_ref().map_or(false, |last| {
            last.db_options == dd.db_options && last.dd_seqno == dd.dd_seqno
        });
        self.last_received_dd = Some(dd.clone());

        if let NeighborState::Down | NeighborState::Attempt = self.state {
            return Ok(()); // Reject the packet
        }

        if let NeighborState::Init = self.state {
            // Make transitiion to with Event (TwoWayReceived)
            unimplemented!("DD in INIT")
        }

        if let NeighborState::TwoWay = self.state {
            return Ok(()); // Ignore
        }

        if let NeighborState::ExStart = self.state {
            // Check for negotiation done
            // a) I+M+MS && empty && dd.rid > rid (set to SLAVE)
            // b) no I+MS && dd.seqno == n.dd && dd.rid < rid (set to MASTER)

            self.options = dd.options;

            if dd.db_options.contains(O::INIT | O::MORE | O::MASTER)
                && dd.lsas.is_empty()
                && pkt.router_id > self.router_id
            {
                self.is_master = false;
                self.state = NeighborState::Exchange;
                tracing::info!("DD: set to SLAVE")
            } else if (dd.db_options & (O::INIT | O::MASTER)).is_empty()
                && dd.dd_seqno == self.dd_seqno
                && pkt.router_id < self.router_id
            {
                self.is_master = true;
                self.state = NeighborState::Exchange;
                tracing::info!("DD: set to MASTER")
            } else {
                return Ok(());
            }
        } else if let NeighborState::Exchange = self.state {
            if is_dup {
                if self.is_master {
                    return Ok(());
                } else {
                    todo!("retransmit")
                }
            }

            // (1) Check inconsistency in M/S flags
            if dd.db_options.contains(O::MASTER) == self.is_master {
                todo!("generated SeqNumberMismatch")
            }

            // (2) Check INIT Flag
            if dd.db_options.contains(O::INIT) {
                todo!("generated SeqNumberMismatch")
            }

            // (3) Check prev. discussed options
            if dd.options != self.options {
                todo!("generated SeqNumberMismatch")
            }

            // (4) Check sequence number
            let is_valid = if self.is_master {
                dd.dd_seqno == self.dd_seqno
            } else {
                dd.dd_seqno == self.dd_seqno + 1
            };
            if !is_valid {
                return Ok(());
            }
        }

        if let NeighborState::Loading | NeighborState::Full = self.state {
            if !self.is_master {
                let last = self.dd_next();
                socket
                    .send_to(
                        &self
                            .wrap(OspfPacketType::DatabaseDescription(last))
                            .write_to_bytes()?,
                        self.n_addr,
                    )
                    .await?;
            }
            return Ok(());
        }

        // (2) General Processing
        tracing::info!("GDDP");

        for lsa in &dd.lsas {
            // Check for valid LSA
        }

        // TODO: clear retranmission list

        // (3) ACK / Steer

        self.summary_list
            .drain(..self.summary_list_free_len)
            .for_each(|_| {});
        self.summary_list_free_len = 0;

        if self.is_master {
            self.dd_seqno += 1;

            if self.summary_list.is_empty() && !dd.db_options.contains(O::MORE) {
                tracing::info!("Exchange done (MASTER)");

                if self.request_list.is_empty() {
                    self.state = NeighborState::Full;
                } else {
                    self.state = NeighborState::Loading;
                    // Start sending LSQ to neigbor TODO
                }
            } else {
                let next = self.dd_next();

                socket
                    .send_to(
                        &self
                            .wrap(OspfPacketType::DatabaseDescription(next))
                            .write_to_bytes()?,
                        self.n_addr,
                    )
                    .await?;
            }
        } else {
            self.dd_seqno = dd.dd_seqno;

            let mut next = self.dd_next();
            if !dd.db_options.contains(O::MORE) && !next.db_options.contains(O::MORE) {
                tracing::info!("Exchange done (SLAVE)");

                if self.request_list.is_empty() {
                    self.state = NeighborState::Full;
                } else {
                    self.state = NeighborState::Loading;
                    // Start sending LSQ to neigbor TODO
                }

                socket
                    .send_to(
                        &self
                            .wrap(OspfPacketType::DatabaseDescription(next))
                            .write_to_bytes()?,
                        self.n_addr,
                    )
                    .await?;
            } else {
                next.db_options.insert(O::MORE);
                socket
                    .send_to(
                        &self
                            .wrap(OspfPacketType::DatabaseDescription(next))
                            .write_to_bytes()?,
                        self.n_addr,
                    )
                    .await?;
            }
        }

        Ok(())
    }

    pub fn wrap(&self, content: OspfPacketType) -> OspfPacket {
        OspfPacket {
            router_id: self.router_id,
            area_id: self.area_id,
            instance_id: self.instance_id,
            content,
        }
    }
}

impl Deref for Neighbor {
    type Target = LinkStateDatabase;
    fn deref(&self) -> &Self::Target {
        &self.db
    }
}

pub struct Config {
    pub router_id: RouterId,
    pub area_id: AreaId,
}

pub async fn poll_rmtx_timers(neighbors: &mut [Neighbor]) {
    for neighbor in neighbors.iter_mut() {
        neighbor.rmtx_timer.tick().await;
    }
    pending::<()>().await
}

pub async fn launch(cfg: Config) -> io::Result<()> {
    router::declare_router()?;

    pcap(File::create(format!("{}.pcapng", current().name()))?)?;

    let mut area = Area::new(cfg.router_id, cfg.area_id);
    let gates = RoutingPort::collect()
        .into_iter()
        .filter(|g| g.name.contains("link"))
        .collect::<Vec<_>>();

    area.db
        .add_router_lsa(RouterLsa {
            flags: RouterLsaFlags::empty(),
            options: OspfOptions::empty(),
            links: Vec::new(),
        })
        .await;

    let mut txx = Vec::new();
    for gate in gates {
        let mut iface = ioctx().add_interface(
            InterfaceDef::ethv6_autocfg(NetworkDevice::from(gate.clone())).router(),
        )?;

        iface.wait_for_link_local().await;

        let mut iface = area.new_interface(iface)?;

        // area.interfaces.push(iface);
        txx.push((gate, ()));
        tokio::spawn(async move {
            // (0) Send a hello packet

            let start_delay = random::<u64>() % iface.hello_interval.as_secs();
            tracing::info!(
                "assigning interface for gate: {} with delay {start_delay}",
                iface.addr
            );
            let mut interval = des::time::interval_at(
                SimTime::now() + Duration::from_secs(start_delay),
                iface.hello_interval,
            );

            let router_id = iface.router_id;

            loop {
                let ip = tokio::select! {
                    _ = interval.tick() => {
                        iface.send_hello().await;
                        continue;
                    }
                    _ = poll_rmtx_timers(&mut iface.neighbors) => {
                        tracing::error!("on retransmit");
                        continue;
                    }
                    pkt = iface.socket.recv() => pkt,
                }?;

                if false {
                    break;
                }

                let Ok(pkt) = OspfPacket::peek_from(&ip.content[..]) else {
                    tracing::error!("invalid packet {ip:?}");
                    continue;
                };

                tracing::trace!(?pkt, "received");

                match &pkt.content {
                    OspfPacketType::Hello(hello) => {
                        iface.on_hello(&ip, &pkt, hello).await;

                        let neighbor = iface
                            .neighbors
                            .iter_mut()
                            .find(|n| n.id == pkt.router_id)
                            .unwrap();

                        // 2-way hello
                        if let NeighborState::Init = neighbor.state
                            && hello.neighbor_ids.contains(&router_id)
                        {
                            // Decide whether ADJ should be created
                            // if no: 2-way
                            // if yes: ExStart

                            iface.send_hello().await;

                            // Reborrow for hello
                            let neighbor = iface
                                .neighbors
                                .iter_mut()
                                .find(|n| n.id == pkt.router_id)
                                .unwrap();
                            neighbor.on_two_way(&mut iface.socket).await?;
                        }
                    }

                    OspfPacketType::DatabaseDescription(dd) => {
                        // Can only be assigned to an existing neighbor
                        let neighbor = iface
                            .neighbors
                            .iter_mut()
                            .find(|n| n.id == pkt.router_id)
                            .unwrap();

                        neighbor.on_dd(&pkt, dd, &mut iface.socket).await?;
                    }
                    _ => {}
                }
            }

            Ok::<(), io::Error>(())
        });
    }

    // let mut socket = RawV6Socket::new(PROTO_OSPF)?;

    // loop {
    //     tokio::select! {
    //         Some((buf, dst)) = srx.recv() => {
    //             socket.send_to(&buf.write_to_bytes()?, dst).await.unwrap();
    //         }
    //         Ok(pkt) = socket.recv() => {
    //             let Ok(p) = OspfPacket::peek_from(pkt.content) else {
    //                 continue;
    //             };
    //             txx[0].1.send(p).await.unwrap();
    //         }
    //     }
    // }

    pending::<()>().await;
    Ok(())
}
