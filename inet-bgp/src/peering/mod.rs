use std::{
    future::Future,
    io::{Error, ErrorKind, Result},
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    pin::Pin,
    time::Duration,
};

use crate::{
    pkt::{BgpNotificationPacket, BgpOpenMessageError},
    BgpNodeInformation, NeighborEgressEvent, NeighborIngressEvent,
};

use super::pkt::{BgpOpenPacket, BgpPacket, BgpPacketKind};

use bytepack::{FromBytestream, ToBytestream};
use des::{
    runtime::random,
    time::{sleep, SimTime},
    tokio::{
        sync::mpsc::{Receiver, Sender},
        task::JoinHandle,
    },
};
use inet::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

mod timers;
mod types;

use self::{
    timers::{Timers, TimersCfg},
    types::*,
};

#[derive(Debug)]
pub(crate) struct NeighborDeamon {
    peering_kind: PeeringKind,

    peer_info: BgpNodeInformation,
    host_info: BgpNodeInformation,
    cfg: BgpPeeringCfg,

    timers: Timers,

    last_keepalive_sent: SimTime,
    last_keepalive_received: SimTime,
    connect_retry_counter: usize,
    delay_open_deadline: SimTime,

    peer_open: BgpOpenPacket,

    tx: Sender<NeighborIngressEvent>,
    rx: Receiver<NeighborEgressEvent>,
    tcp_rx: Receiver<TcpStream>,
}

#[derive(Debug, Clone)]
pub(crate) struct BgpPeeringCfg {
    // mandatory
    pub(crate) hold_time: Duration,
    pub(crate) keepalive_time: Duration,
    pub(crate) connect_retry_time: Duration,

    // optional
    pub(crate) allow_auto_start: bool,
    pub(crate) allow_auto_stop: bool,
    pub(crate) colliosion_detect: bool,
    pub(crate) damp_peer_oscillation: bool,
    pub(crate) delay_open: bool,
    pub(crate) delay_open_time: Duration,
    pub(crate) idle_hold_time: Duration,
    pub(crate) passiv_tcp_estab: bool,
    pub(crate) notif_without_open: bool,
}

impl Default for BgpPeeringCfg {
    fn default() -> Self {
        Self {
            hold_time: Duration::from_secs(180),
            keepalive_time: Duration::from_secs(60),
            connect_retry_time: Duration::from_secs(30),

            allow_auto_start: false,
            allow_auto_stop: false,
            colliosion_detect: false,
            damp_peer_oscillation: false,
            delay_open: false,
            delay_open_time: Duration::ZERO,
            idle_hold_time: Duration::ZERO,
            passiv_tcp_estab: false,
            notif_without_open: false,
        }
    }
}

pub(crate) enum NeighborDeamonState {
    Idle,
    Connect(Pin<Box<dyn Future<Output = Result<TcpStream>> + Send>>),
    Active,
    ActiveDelayOpen(TcpStream),
    OpenSent(TcpStream),
    OpenConfirm(TcpStream),
    Established(TcpStream),
}

pub(crate) struct NeighborHandle {
    pub(crate) tx: Sender<NeighborEgressEvent>,
    pub(crate) task: JoinHandle<Result<()>>,
}

impl NeighborDeamon {
    pub fn new(
        host_info: BgpNodeInformation,
        peer_info: BgpNodeInformation,
        tx: Sender<NeighborIngressEvent>,
        rx: Receiver<NeighborEgressEvent>,
        tcp_rx: Receiver<TcpStream>,
    ) -> Self {
        Self {
            peering_kind: PeeringKind::for_as(host_info.as_num, peer_info.as_num),

            host_info,
            peer_info,
            cfg: BgpPeeringCfg::default(),

            timers: Timers::new(TimersCfg::default()),

            last_keepalive_received: SimTime::ZERO,
            last_keepalive_sent: SimTime::ZERO,
            connect_retry_counter: 0,
            delay_open_deadline: SimTime::ZERO,

            peer_open: BgpOpenPacket {
                version: 0,
                as_number: 0,
                hold_time: 0,
                identifier: 0,
                options: Vec::new(),
            },

            tx,
            rx,
            tcp_rx,
        }
    }

    fn open_pkt(&self) -> BgpPacket {
        BgpPacket {
            marker: u128::MAX,
            kind: BgpPacketKind::Open(BgpOpenPacket {
                version: 4,
                as_number: self.host_info.as_num,
                hold_time: self.cfg.hold_time.as_secs() as u16,
                identifier: self.host_info.addr.into(),
                options: Vec::new(),
            }),
        }
    }

    fn keepalive(&self) -> BgpPacket {
        BgpPacket {
            marker: u128::MAX,
            kind: BgpPacketKind::Keepalive(),
        }
    }

    fn try_recv_incoming_tcp_stream(&mut self) -> Option<TcpStream> {
        loop {
            match self.tcp_rx.try_recv() {
                Ok(stream) => {
                    let n = stream.try_read(&mut []);
                    if let Ok(n) = n {
                        if n == 0 {
                            // stream has expired, remove it
                            continue;
                        }
                    }
                    return Some(stream);
                }
                Err(_e) => return None,
            }
        }
    }

    pub(crate) async fn deploy(self) -> Result<()> {
        self._deploy().await.map_err(|e| {
            tracing::error!(">>> {e}");
            e
        })
    }

    async fn _deploy(mut self) -> Result<()> {
        sleep(Duration::from_secs_f64(random::<f64>() * 0.25)).await;

        const BUF_SIZE: usize = 1024;
        let mut buf = [0; BUF_SIZE];

        let mut state = NeighborDeamonState::Idle;
        loop {
            use NeighborDeamonState::*;
            use NeighborEgressEvent::*;

            match state {
                Idle => {
                    // RFC requires
                    // - no resource allocation
                    // - denying of all incoming connections
                    let event = tokio::select! {
                        event = self.rx.recv() => event,
                        _ = self.tcp_rx.recv() => {
                            tracing::warn!("[idle] dropping incoming tcp connection");
                            state = Idle;
                            continue;
                        }
                    };

                    let Some(event) = event else {
                        return Err(Error::new(ErrorKind::BrokenPipe, "subtask shutdown, due to master error"));
                    };

                    match event {
                        Start => {
                            // RFC requires:
                            // - init of BGP resources
                            // - ConnectRetryCounter = 0
                            // - ConnectRetryTimerStart #TODO
                            // - listen to incoming connections
                            self.connect_retry_counter = 0;

                            if self.cfg.passiv_tcp_estab {
                                // - change to Active
                                state = Active;
                            } else {
                                // - open TCP connection to client
                                // - change to Connect
                                if let Some(incoming) = self.try_recv_incoming_tcp_stream() {
                                    state = Connect(Box::pin(futures::future::ok(incoming)));
                                    continue;
                                }

                                tracing::debug!("[idle] trying to establish own connection");

                                state = Connect(Box::pin(TcpStream::connect(SocketAddr::V4(
                                    SocketAddrV4::new(self.peer_info.addr, 179),
                                ))));
                            }
                        }
                        _ => {}
                    }
                }

                // The provided stream at inital call is either
                // initiated by this client, or accept as incoming
                Connect(stream) => {
                    let mut stream = tokio::select! {
                        stream = stream => stream,
                        _ = sleep(self.cfg.connect_retry_time) => {
                            tracing::debug!("[connect] connect_retry_timer expired, establishing new TCP connection");

                            // - drop old connection
                            // - create new one
                            state = Connect(Box::pin(TcpStream::connect(SocketAddr::V4(
                                SocketAddrV4::new(self.peer_info.addr, 179),
                            ))));
                            continue;
                        }
                    };

                    // This incoming check will only succeed, stream was client
                    // initiated, bc if not, the queue should be empty
                    if let Some(incoming) = self.try_recv_incoming_tcp_stream() {
                        // TODO: check source validity
                        // two simultaneous tcp stream where created
                        // -> choose the one where the client has the higher ip
                        let stream_rank = u32::from(self.host_info.addr);
                        let incoming_rank = u32::from(self.peer_info.addr);

                        tracing::info!(
                            stream_rank,
                            incoming_rank,
                            "[connect] simultaneous connection detected",
                        );

                        if incoming_rank > stream_rank {
                            tracing::trace!(
                                "[connect] switching to incoming stream, over own connection"
                            );
                            stream = Ok(incoming);
                        }
                    }

                    let mut stream = match stream {
                        Ok(stream) => {
                            tracing::debug!(
                                "[connect] tcp connection established (local:{} -> peer:{})",
                                stream.local_addr()?.port(),
                                stream.peer_addr()?.port()
                            );
                            stream
                        }
                        Err(_e) => {
                            state = Active;
                            continue;
                        }
                    };

                    if self.cfg.delay_open {
                        sleep(self.cfg.delay_open_time).await;
                        todo!()
                    } else {
                        // RFC requires
                        // - timer reset (done)
                        // - BGP init + send OPEN
                        // - HoldTimer = 4min
                        // - State = OpenSent
                        tracing::debug!("[connect] sending OPEN message");
                        if let Err(e) = stream.write_all(&self.open_pkt().to_buffer()?).await {
                            tracing::error!("> {e}");
                            state = Active;
                            continue;
                        }
                        state = OpenSent(stream);
                    }
                }

                Active => {
                    tokio::select! {
                        stream = self.tcp_rx.recv() => {
                            let Some(mut stream) = stream else {
                                todo!()
                            };

                            match stream.try_read(&mut []) {
                                Ok(0) => {
                                    state = Active;
                                    continue
                                },
                                _ => {}
                            }


                            if self.cfg.delay_open {
                                tracing::info!("[active] accepted incoming tcp connection, delay open");
                                self.connect_retry_counter = 0;
                                self.delay_open_deadline = SimTime::now() + self.cfg.delay_open_time;
                                state = ActiveDelayOpen(stream);
                            } else {
                                tracing::info!("[active] accepted incoming tcp connection");
                                stream.write_all(&self.open_pkt().to_buffer()?).await?;
                                state = OpenSent(stream)
                            }
                        }

                        event = self.rx.recv() => match event.unwrap() {
                            Stop => {
                                self.connect_retry_counter = 0;
                                state = Idle;
                            }
                            _ => state = Active
                        },

                        _ = sleep(self.cfg.connect_retry_time) => {
                            // Listening has not brough succes,
                            tracing::info!("trying to establish own connection");
                            let stream = TcpStream::connect(SocketAddr::V4(SocketAddrV4::new(
                                self.peer_info.addr,
                                179,
                            )));
                            state = Connect(Box::pin(stream));
                        }
                    }
                }

                ActiveDelayOpen(mut stream) => {
                    let dur = self
                        .delay_open_deadline
                        .checked_duration_since(SimTime::now())
                        .unwrap_or(Duration::ZERO);

                    tokio::select! {
                        n = stream.read(&mut buf) => {
                            // TODO: missing hold timer funny buisness
                            let n = n?;
                            let bgp = BgpPacket::from_buffer(&buf[..n])?;
                            match bgp.kind {
                                BgpPacketKind::Open(open) => {
                                    self.peering_kind = match self.check_open(&open) {
                                        Ok(kind) => kind,
                                        Err(e) => {
                                            tracing::error!("[active] delayed open, recevied faulty OPEN message: {e:?}");
                                            stream.write_all(&BgpPacket {
                                                marker: u128::MAX,
                                                kind: BgpPacketKind::Notification(BgpNotificationPacket::OpenMessageError(e))
                                            }.to_buffer()?).await?;
                                            state = Idle;
                                            continue;
                                        }
                                    };
                                    self.peer_open = open;

                                    tracing::info!("[active] delayed open, recevied OPEN packet");
                                    stream.write_all(&self.open_pkt().to_buffer()?).await?;
                                    stream.write_all(&self.keepalive().to_buffer()?).await?;
                                    state = OpenSent(stream);
                                },
                                _ => todo!()
                            }
                        }

                        _ = sleep(dur) => {
                            // DELAY OPEN TIMER EXPIRED
                            tracing::info!("[active] delayed open, sending OPEN packet");
                            self.connect_retry_counter = 0;
                            stream.write_all(&self.open_pkt().to_buffer()?).await?;
                            state = OpenSent(stream);
                        }
                    }
                }

                OpenSent(mut stream) => {
                    tokio::select! {
                        incoming = self.tcp_rx.recv() => {
                            // NON STANDARD RFC
                            let Some(incoming) = incoming else {
                                todo!()
                            };

                            let stream_rank = u32::from(self.host_info.addr);
                            let incoming_rank = u32::from(self.peer_info.addr);

                            tracing::info!(stream_rank, incoming_rank, "[opensent] simultaneous connection ");

                            if incoming_rank > stream_rank {
                                tracing::trace!("[opensent] switching to incoming stream, discarding own");
                                stream = incoming;

                                // Switching to a new stream requires
                                // a new sending of the OPEN pkt
                                tracing::info!("[opensent] resending OPEN message");
                                stream.write_all(&self.open_pkt().to_buffer()?).await?;
                            }

                            state = OpenSent(stream)
                        }

                       // CASE 1: Stop message
                       // - drop connection, send CEASE message
                       // - return to IDLE
                       event = self.rx.recv() => match event.unwrap() {
                            Stop => {
                                stream.write_all(&BgpPacket {
                                    marker: u128::MAX,
                                    kind: BgpPacketKind::Notification(BgpNotificationPacket::Cease()),
                                }.to_buffer()?).await?;
                                self.connect_retry_counter = 0;
                                // TODO: peer oscilation
                                state = Idle;
                            },
                            _ => state = OpenSent(stream)
                       },

                       // CASE 2: Hold timer expures
                       _ = sleep(self.cfg.hold_time) => {
                        // The stream could be created, but the other side does not seem to anweser
                        // keepalive is dead
                        tracing::error!("[opensent] peer connected, but unresponsive -> terminating");
                        drop(stream);
                        state = Active;
                    }


                       // CASE 3: OPEN message received
                       // - if TCP-FAIL: close, change to ACTIVE
                       // - if OPEN-INVALID: send NOTIF and close, return to IDLE
                       // - else, send KEEPALIVE, change to OPENCONFIRM
                       // - configure hold time, set keepalive timer
                        n = stream.read(&mut buf) => {
                            let n = match n {
                                Ok(0) => {
                                    // peer decieded the current stream is not valid,
                                    // wait for incoming stream
                                    tracing::warn!("[opensent] connection closed, assuming second connection");
                                    drop(stream);
                                    state = Active;
                                    continue
                                }
                                Ok(n) => n,
                                Err(e) => {
                                    tracing::error!("[opensent] connection broke, assuming second connection: {e:?}");
                                    state = Active;
                                    continue
                                }
                            };

                            let bgp = BgpPacket::from_buffer(&buf[..n])?;
                            match bgp.kind {
                                BgpPacketKind::Open(open) => {
                                    self.peering_kind = match self.check_open(&open) {
                                        Ok(kind) => kind,
                                        Err(e) => {
                                            tracing::error!("[opensent] recevied faulty OPEN message: {e:?}");
                                            stream.write_all(&BgpPacket {
                                                marker: u128::MAX,
                                                kind: BgpPacketKind::Notification(BgpNotificationPacket::OpenMessageError(e))
                                            }.to_buffer()?).await?;
                                            state = Idle;
                                            continue;
                                        }
                                    };
                                    self.peer_open = open;

                                    tracing::info!("[opensent] received OPEN message, waiting for keepalive");
                                    stream.write_all(&self.keepalive().to_buffer()?).await?;
                                    self.cfg.hold_time = self.cfg.hold_time.min(Duration::from_secs(self.peer_open.hold_time as u64));
                                    state = OpenConfirm(stream);
                                },
                                BgpPacketKind::Keepalive() => {
                                    self.last_keepalive_received = SimTime::now();
                                    state = OpenSent(stream)
                                }
                                _ => {
                                    state = OpenSent(stream)
                                }
                            }
                        }
                    }
                }

                OpenConfirm(mut stream) => {
                    tokio::select! {

                        // CASE 1: Stop
                        event = self.rx.recv() => match event.unwrap() {
                            Stop => {
                                stream.write_all(&BgpPacket {
                                    marker: u128::MAX,
                                    kind: BgpPacketKind::Notification(BgpNotificationPacket::Cease())
                                }.to_buffer()?).await?;
                                self.connect_retry_counter = 0;
                                state = Idle;
                            },
                            _ => state = OpenConfirm(stream),
                        },

                        // CASE 2/3: Hold timer expires + Keepalive timer expires
                        _ = sleep(self.cfg.keepalive_time) => {
                            if self.last_keepalive_received.elapsed() > self.cfg.hold_time {
                                stream.write_all(&BgpPacket {
                                    marker: u128::MAX,
                                    kind: BgpPacketKind::Notification(BgpNotificationPacket::HoldTimerExpires())
                                }.to_buffer()?).await?;
                                self.connect_retry_counter += 1;
                                state = Idle;
                                continue;
                            }

                            tracing::info!("[openconfirm] sending KEEPALIVE");
                            let keepalive = BgpPacket {
                                marker: u128::MAX,
                                kind: BgpPacketKind::Keepalive()
                            };
                            stream.write_all(&keepalive.to_buffer()?).await?;
                            self.last_keepalive_sent = SimTime::now();
                            state = OpenConfirm(stream);
                        }



                        n = stream.read(&mut buf) => {
                            let n = match n {
                                Ok(n) => n,
                                Err(e) => {
                                    tracing::error!("{e:?}");
                                    state = Idle;
                                    continue
                                }
                            };

                            let bgp = BgpPacket::from_buffer(&buf[..n])?;
                            match bgp.kind {
                                BgpPacketKind::Open(_) => {
                                    todo!("needs collision mngt")
                                }

                                BgpPacketKind::Keepalive() => {
                                    // TODO: check peer

                                    tracing::info!("[openconfirm] established BGP {{ {:?} <--> {:?} }}", self.host_info.str(), self.peer_info.str());
                                    self.last_keepalive_received = SimTime::now();
                                    state = Established(stream)
                                },
                                _ => state = OpenConfirm(stream)
                            }
                        }

                    }
                }

                Established(mut stream) => {
                    let time_since_keepalive = SimTime::now() - self.last_keepalive_sent;
                    let time_to_keepalive = self
                        .cfg
                        .keepalive_time
                        .checked_sub(time_since_keepalive)
                        .unwrap_or(Duration::ZERO);

                    tokio::select! {
                        n = stream.read(&mut buf) => {
                            let n = n?;
                            let bgp = BgpPacket::from_buffer(&buf[..n])?;

                            match bgp.kind {
                                BgpPacketKind::Keepalive() => {
                                    self.last_keepalive_received = SimTime::now();
                                }
                                _ => todo!()
                            }
                        }
                        _ = sleep(time_to_keepalive) => {
                            if self.last_keepalive_received.elapsed() > self.cfg.hold_time {
                                stream.write_all(&BgpPacket {
                                    marker: u128::MAX,
                                    kind: BgpPacketKind::Notification(BgpNotificationPacket::HoldTimerExpires())
                                }.to_buffer()?).await?;
                                state = Idle;
                                continue;
                            }

                            // Keepalive need to be sent
                            let keepalive = BgpPacket {
                                marker: u128::MAX,
                                kind: BgpPacketKind::Keepalive(),
                            };
                            self.last_keepalive_sent = SimTime::now();
                            stream.write_all(&keepalive.to_buffer()?).await?;
                        }
                    };

                    state = Established(stream)
                }
            }
        }
    }

    fn check_open(
        &self,
        open: &BgpOpenPacket,
    ) -> std::result::Result<PeeringKind, BgpOpenMessageError> {
        if open.version != 4 {
            return Err(BgpOpenMessageError::UnsupportedVersionNumber);
        }

        if self.peer_info.as_num != open.as_number {
            dbg!(&self.peer_info, &open);
            return Err(BgpOpenMessageError::BadPeerAs);
        }

        if self.peer_info.addr != Ipv4Addr::from(open.identifier) {
            return Err(BgpOpenMessageError::BadBgpIdentifer);
        }

        if !open.options.is_empty() {
            return Err(BgpOpenMessageError::UnsupportedOptionalParameter);
        }

        if Duration::from_secs(open.hold_time as u64) < self.cfg.keepalive_time {
            return Err(BgpOpenMessageError::UnacceptableHoldTime);
        }

        Ok(if open.as_number == self.host_info.as_num {
            PeeringKind::Internal
        } else {
            PeeringKind::External
        })
    }
}
