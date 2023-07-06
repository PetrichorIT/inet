use bytepack::ToBytestream;
use des::{prelude::*, time::*};
use inet::TcpStream;
use std::{
    io::{Error, ErrorKind, Result},
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    time::Duration,
};
use tokio::{
    io::AsyncWriteExt,
    sync::mpsc::{Receiver, Sender},
    task::JoinHandle,
};

use crate::{peering::stream::BgpStream, pkt::BgpUpdatePacket};

use self::{
    timers::{Timer, Timers, TimersCfg},
    types::*,
};
use super::{
    pkt::{BgpNotificationPacket, BgpOpenMessageError, BgpOpenPacket, BgpPacket, BgpPacketKind},
    BgpNodeInformation, NeighborEgressEvent, NeighborIngressEvent,
};

mod stream;
mod timers;
mod types;

pub use types::BgpPeeringCfg;

#[derive(Debug)]
pub struct NeighborDeamon {
    peering_kind: PeeringKind,

    peer_info: BgpNodeInformation,
    host_info: BgpNodeInformation,
    pub cfg: BgpPeeringCfg,

    timers: Timers,

    last_keepalive_sent: SimTime,
    last_keepalive_received: SimTime,
    connect_retry_counter: usize,

    peer_open: BgpOpenPacket,

    tx: Sender<NeighborIngressEvent>,
    rx: Receiver<NeighborEgressEvent>,
    tcp_rx: Receiver<TcpStream>,
}

pub(crate) struct NeighborHandle {
    pub(crate) up: bool,
    pub(crate) tx: Sender<NeighborEgressEvent>,

    #[allow(unused)]
    pub(crate) task: JoinHandle<Result<()>>,
}

macro_rules! write_stream {
    ($stream:ident, $t:expr) => {
        $stream.write_all(&$t.to_buffer()?).await?;
    };
}

impl NeighborDeamon {
    pub fn new(
        host_info: BgpNodeInformation,
        peer_info: BgpNodeInformation,
        tx: Sender<NeighborIngressEvent>,
        rx: Receiver<NeighborEgressEvent>,
        tcp_rx: Receiver<TcpStream>,
        cfg: BgpPeeringCfg,
    ) -> Self {
        Self {
            peering_kind: PeeringKind::for_as(host_info.as_num, peer_info.as_num),

            host_info,
            peer_info,
            cfg,
            timers: Timers::new(TimersCfg::default()),

            last_keepalive_received: SimTime::ZERO,
            last_keepalive_sent: SimTime::ZERO,
            connect_retry_counter: 0,

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
                hold_time: self.timers.cfg.hold_time.as_secs() as u16,
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

    fn notif(&self, kind: BgpNotificationPacket) -> BgpPacket {
        BgpPacket {
            marker: u128::MAX,
            kind: BgpPacketKind::Notification(kind),
        }
    }

    fn update(&self, update: BgpUpdatePacket) -> BgpPacket {
        BgpPacket {
            marker: u128::MAX,
            kind: BgpPacketKind::Update(update),
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

    pub async fn deploy(self) -> Result<()> {
        self._deploy().await.map_err(|e| {
            tracing::error!(">>> {e}");
            e
        })
    }

    async fn _deploy(mut self) -> Result<()> {
        use NeighborDeamonState::*;
        use NeighborEgressEvent::*;
        use NeighborIngressEvent::*;

        sleep(Duration::from_secs_f64(random::<f64>() * 0.25)).await;
        tracing::debug!("@init");

        let mut state = Idle;
        loop {
            // tracing::trace!("{:?} {:?}", state, self.timers);

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
                            tracing::info!("[idle] starting peering with {}", self.peer_info.str());
                            // RFC requires:
                            // - init of BGP resources
                            // - ConnectRetryCounter = 0
                            // - ConnectRetryTimerStart #TODO
                            // - listen to incoming connections
                            self.connect_retry_counter = 0;
                            self.timers.enable_timer(Timer::ConnectionRetryTimer);

                            if self.cfg.passiv_tcp_estab {
                                // - change to Active
                                state = Active;
                            } else {
                                // - open TCP connection to client
                                // - change to Connect
                                if let Some(incoming) = self.try_recv_incoming_tcp_stream() {
                                    state = Connect(Box::pin(std::future::ready(Ok(incoming))));
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
                        event = self.rx.recv() => match event.unwrap() {
                            Stop => {
                                self.connect_retry_counter = 0;
                                self.timers.disable_timer(Timer::ConnectionRetryTimer);
                                state = Idle;
                                continue;
                            },
                            _ => {
                                todo!()
                            }
                        },
                        timer = self.timers.next() => {
                            assert_eq!(timer, Timer::ConnectionRetryTimer);
                            tracing::debug!("[connect] timer expired, establishing new TCP connection");

                            self.timers.disable_timer(Timer::DelayOpenTimer); // redundant, delay open has its own state
                            self.timers.enable_timer(Timer::ConnectionRetryTimer);

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

                        tracing::debug!(
                            stream_rank,
                            incoming_rank,
                            "[connect] simultaneous connection detected",
                        );

                        if incoming_rank > stream_rank {
                            tracing::debug!(
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
                        Err(e) => {
                            tracing::error!("failed to connect {e}");
                            state = Active;
                            continue;
                        }
                    };

                    if self.cfg.delay_open {
                        sleep(self.timers.cfg.delay_open_time).await;
                        todo!()
                    } else {
                        // RFC requires
                        // - timer reset (done)
                        // - BGP init + send OPEN
                        // - HoldTimer = 4min
                        // - State = OpenSent

                        self.timers.disable_timer(Timer::ConnectionRetryTimer);
                        self.timers.enable_timer(Timer::HoldTimer);

                        tracing::debug!("[connect] sending OPEN message");
                        if let Err(e) = stream.write_all(&self.open_pkt().to_buffer()?).await {
                            tracing::error!("> {e}");
                            state = Active;
                            continue;
                        }
                        state = OpenSent(BgpStream::new(stream));
                    }
                }

                Active => {
                    tokio::select! {
                        // ManualStop (Event 2)
                        event = self.rx.recv() => match event.unwrap() {
                            Stop => {
                                self.connect_retry_counter = 0;
                                self.timers.disable_timer(Timer::DelayOpenTimer);
                                self.timers.disable_timer(Timer::ConnectionRetryTimer);
                                state = Idle;
                            }
                            _ => state = Active
                        },

                        timer = self.timers.next() => {
                            assert_eq!(timer, Timer::ConnectionRetryTimer);
                            tracing::debug!("trying to establish own connection");
                            self.timers.enable_timer(Timer::ConnectionRetryTimer);
                            let stream = TcpStream::connect(SocketAddr::V4(SocketAddrV4::new(
                                self.peer_info.addr,
                                179,
                            )));
                            state = Connect(Box::pin(stream));
                        },

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
                                tracing::debug!("[active] accepted incoming tcp connection, delay open");
                                self.connect_retry_counter = 0;
                                self.timers.disable_timer(Timer::ConnectionRetryTimer);
                                self.timers.enable_timer(Timer::DelayOpenTimer);
                                state = ActiveDelayOpen(BgpStream::new(stream));
                            } else {
                                tracing::debug!("[active] accepted incoming tcp connection");
                                self.timers.disable_timer(Timer::ConnectionRetryTimer);
                                stream.write_all(&self.open_pkt().to_buffer()?).await?;
                                self.timers.enable_timer(Timer::HoldTimer);
                                state = OpenSent(BgpStream::new(stream))
                            }
                        }
                    }
                }

                ActiveDelayOpen(mut stream) => {
                    tokio::select! {
                        done = stream.recv() => {
                            let done = done?;
                            if done {
                                todo!()
                            }
                            let Some(bgp) = stream.next()? else {
                                state = ActiveDelayOpen(stream);
                                continue
                            };
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

                                    tracing::debug!("[active] delayed open, recevied OPEN packet");
                                    self.timers.disable_timer(Timer::ConnectionRetryTimer);
                                    self.timers.disable_timer(Timer::DelayOpenTimer);

                                    stream.write_all(&self.open_pkt().to_buffer()?).await?;
                                    stream.write_all(&self.keepalive().to_buffer()?).await?;

                                    self.timers.enable_timer(Timer::HoldTimer);
                                    self.timers.enable_timer(Timer::KeepaliveTimer);

                                    state = OpenConfirm(stream);
                                },

                                BgpPacketKind::Notification(notif) => {
                                    // delay open IS running, since we are in delay open state
                                    tracing::error!("[active] delayed open, got nofif {notif:?}");
                                    self.timers.disable_timer(Timer::ConnectionRetryTimer);
                                    self.timers.disable_timer(Timer::DelayOpenTimer);
                                    state = Idle;
                                }
                                _ => todo!()
                            }
                        }

                        timer = self.timers.next() => match timer {
                            Timer::DelayOpenTimer =>   {
                                // DELAY OPEN TIMER EXPIRED
                                tracing::debug!("[active] delayed open, sending OPEN packet");
                                self.connect_retry_counter = 0;
                                self.timers.disable_timer(Timer::DelayOpenTimer);
                                stream.write_all(&self.open_pkt().to_buffer()?).await?;
                                self.timers.enable_timer(Timer::HoldTimer);
                                state = OpenSent(stream);
                            },
                            _ => todo!()
                        }
                    }
                }

                OpenSent(mut stream) => {
                    tokio::select! {
                        // CASE 1: Stop message
                        // - drop connection, send CEASE message
                        // - return to IDLE
                        event = self.rx.recv() => match event.unwrap() {
                            Stop => {
                                write_stream!(stream, self.notif(BgpNotificationPacket::Cease()));
                                self.timers.disable_timer(Timer::ConnectionRetryTimer);
                                self.connect_retry_counter = 0;
                                // TODO: peer osicillation
                                state = Idle;
                            },
                            _ => state = OpenSent(stream)
                        },

                        timer = self.timers.next() => match timer {
                            Timer::HoldTimer => {
                                tracing::error!("[opensent] peer connected, but unresponsive -> terminating");
                                write_stream!(stream, self.notif(BgpNotificationPacket::HoldTimerExpires()));
                                self.timers.disable_timer(Timer::ConnectionRetryTimer);
                                self.connect_retry_counter += 1;
                                // TODO: peer oscialltion
                                state = Idle;
                            }
                            _ => todo!()
                        },

                        // Second TCP tracing
                        incoming = self.tcp_rx.recv() => {
                            // NON STANDARD RFC
                            let Some(incoming) = incoming else {
                                todo!()
                            };

                            let stream_rank = u32::from(self.host_info.addr);
                            let incoming_rank = u32::from(self.peer_info.addr);

                            tracing::debug!(stream_rank, incoming_rank, "[opensent] simultaneous connection ");

                            if incoming_rank > stream_rank {
                                tracing::debug!("[opensent] switching to incoming stream, discarding own");
                                stream = BgpStream::new(incoming);

                                // Switching to a new stream requires
                                // a new sending of the OPEN pkt
                                tracing::debug!("[opensent] resending OPEN message");
                                stream.write_all(&self.open_pkt().to_buffer()?).await?;
                            }

                            state = OpenSent(stream)
                        }


                       // CASE 3: OPEN message received
                       // - if TCP-FAIL: close, change to ACTIVE
                       // - if OPEN-INVALID: send NOTIF and close, return to IDLE
                       // - else, send KEEPALIVE, change to OPENCONFIRM
                       // - configure hold time, set keepalive timer
                        done = stream.recv() => {
                            match done {
                                Ok(true) => {
                                    // peer decieded the current stream is not valid,
                                    // wait for incoming stream
                                    tracing::warn!("[opensent] connection closed, assuming second connection");
                                    self.timers.disable_timer(Timer::KeepaliveTimer);
                                    self.timers.enable_timer(Timer::ConnectionRetryTimer);
                                    state = Active;
                                    continue
                                }
                                Ok(false) => {},
                                Err(e) => {
                                    tracing::error!("[opensent] connection broke, assuming second connection: {e:?}");
                                    self.timers.enable_timer(Timer::ConnectionRetryTimer);
                                    state = Active;
                                    continue
                                }
                            };

                            let Some(bgp) = stream.next()? else {
                                state = OpenSent(stream);
                                continue
                            };
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

                                    self.timers.disable_timer(Timer::DelayOpenTimer);
                                    self.timers.disable_timer(Timer::ConnectionRetryTimer);

                                    tracing::debug!("[opensent] received OPEN message, waiting for keepalive");
                                    write_stream!(stream, self.keepalive());

                                    self.timers.enable_timer(Timer::KeepaliveTimer);

                                    let hold_time = self.timers.cfg.hold_time.min(Duration::from_secs(self.peer_open.hold_time as u64));
                                    self.timers.cfg.hold_time = hold_time;
                                    state = OpenConfirm(stream);
                                },

                                // NON RFC
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
                                write_stream!(stream, self.notif(BgpNotificationPacket::Cease()));
                                self.connect_retry_counter += 1; // TODO: diff automatic or manual
                                self.timers.disable_timer(Timer::ConnectionRetryTimer);
                                state = Idle;
                            },
                            _ => state = OpenConfirm(stream),
                        },

                        timer = self.timers.next() => match timer {
                            Timer::HoldTimer => {
                                write_stream!(stream, self.notif(BgpNotificationPacket::HoldTimerExpires()));
                                self.timers.disable_timer(Timer::ConnectionRetryTimer);
                                self.connect_retry_counter += 1;
                                // TODO: peer ociall
                                state = Idle;
                            }

                            Timer::KeepaliveTimer => {
                                tracing::debug!("[openconfirm] sending KEEPALIVE");
                                write_stream!(stream, self.keepalive());
                                self.last_keepalive_sent = SimTime::now();
                                self.timers.enable_timer(Timer::KeepaliveTimer);
                                state = OpenConfirm(stream);
                            }
                            _ => todo!()
                        },


                        done = stream.recv() => {
                            match done {
                                Ok(true) => todo!(),
                                Ok(false) => {},
                                Err(e) => {
                                    tracing::error!("{e:?}");
                                    state = Idle;
                                    continue
                                }
                            };

                            let Some(bgp) = stream.next()? else {
                                state = OpenConfirm(stream);
                                continue;
                            };
                            match bgp.kind {
                                BgpPacketKind::Open(_) => {
                                    todo!("needs collision mngt")
                                }

                                BgpPacketKind::Notification(notif) => {
                                    tracing::error!("[openconfirm] got notif: {notif:?}");
                                    self.timers.disable_timer(Timer::ConnectionRetryTimer);
                                    self.connect_retry_counter += 1;
                                    // TODO: peer oscil
                                    state = Idle;
                                }

                                BgpPacketKind::Keepalive() => {
                                    tracing::info!("[openconfirm] established BGP {{ {:?} <--> {:?} }}", self.host_info.str(), self.peer_info.str());
                                    self.last_keepalive_received = SimTime::now();
                                    self.timers.enable_timer(Timer::HoldTimer);
                                    self.tx.send(ConnectionEstablished(self.peer_info.clone())).await.unwrap();
                                    state = Established(stream)
                                },
                                _ => state = OpenConfirm(stream)
                            }
                        }

                    }
                }

                Established(stream) => state = self.process_state_established(stream).await?,
            }
        }
    }

    async fn process_state_established(
        &mut self,
        mut stream: BgpStream,
    ) -> Result<NeighborDeamonState> {
        use NeighborDeamonState::*;
        use NeighborEgressEvent::*;
        use NeighborIngressEvent::*;
        loop {
            tokio::select! {
                event = self.rx.recv() => match event.expect("BGP deamon crashed -- crashing worker process") {
                    Stop => {
                        tracing::info!("terminating connection");
                        write_stream!(stream, self.notif(BgpNotificationPacket::Cease()));
                        self.timers.disable_timer(Timer::ConnectionRetryTimer);
                        self.tx.send(ConnectionLost(self.peer_info.clone())).await.expect("failed");
                        // TODO: peer osci
                        self.connect_retry_counter = 0;
                        return Ok(Idle);
                    },
                    Advertise(update) => {
                        write_stream!(stream, self.update(update));
                        continue
                    }
                    _ => todo!()
                },

                timer = self.timers.next() => match timer {
                    Timer::HoldTimer => {
                        write_stream!(stream, self.notif(BgpNotificationPacket::HoldTimerExpires()));
                        self.timers.disable_timer(Timer::ConnectionRetryTimer);
                        self.connect_retry_counter += 1;
                        // TODO: peer osci
                        return Ok(Idle);
                    }
                    Timer::KeepaliveTimer => {
                        write_stream!(stream, self.keepalive());
                        self.timers.enable_timer(Timer::KeepaliveTimer);
                        continue
                    }
                    _ => todo!()
                },

                done = stream.recv() => match done {
                    Ok(true) => {
                        tracing::warn!("closed connection");
                        return Ok(Idle);
                    },
                    Ok(false) => {},
                    Err(_e) => {
                        todo!()
                    }
                }
            };

            while let Some(bgp) = stream.next()? {
                match bgp.kind {
                    BgpPacketKind::Keepalive() => {
                        self.last_keepalive_received = SimTime::now();
                        self.timers.enable_timer(Timer::HoldTimer);
                    }
                    BgpPacketKind::Update(update) => {
                        self.timers.enable_timer(Timer::HoldTimer);
                        self.tx
                            .send(Update(self.peer_info.addr, update))
                            .await
                            .expect("deamon dead");
                    }
                    BgpPacketKind::Notification(notif) => {
                        self.connect_retry_counter += 1;
                        self.timers.enable_timer(Timer::ConnectionRetryTimer);
                        tracing::warn!("connection lost ({notif:?})");
                        self.tx
                            .send(ConnectionLost(self.peer_info.clone()))
                            .await
                            .expect("deamon dead");
                        return Ok(Idle);
                    }
                    _ => todo!("{:?}", bgp.kind),
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

        if Duration::from_secs(open.hold_time as u64) < self.timers.cfg.keepalive_time {
            return Err(BgpOpenMessageError::UnacceptableHoldTime);
        }

        Ok(if open.as_number == self.host_info.as_num {
            PeeringKind::Internal
        } else {
            PeeringKind::External
        })
    }
}
