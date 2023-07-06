//! The Transmission Control Protocol (TCP)
#![allow(unused)]

use bytepack::{FromBytestream, ToBytestream};
use des::{
    prelude::{module_path, schedule_in, GateRef, Message},
    time::SimTime,
};
use fxhash::{FxBuildHasher, FxHashMap};
use std::{
    collections::VecDeque,
    io::{Error, ErrorKind, Result},
    net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4},
    sync::{atomic::Ordering, Arc},
    task::Waker,
    time::Duration,
};
use tokio::sync::oneshot;
use tracing::{
    field::{debug, Empty, Field},
    instrument, Level, Span,
};

use crate::{
    interface::{IfId, KIND_IO_TIMEOUT},
    socket::{Fd, SocketIfaceBinding, SocketType},
};
use inet_types::{
    ip::{IpPacket, IpPacketRef, IpVersion, Ipv4Flags, Ipv4Packet, Ipv6Packet},
    tcp::{TcpFlags, TcpOption, TcpPacket, PROTO_TCP},
};

mod buffer;
pub use self::buffer::*;

mod config;
pub use self::config::*;

mod types;
pub(crate) use types::TcpState;
use types::*;

pub(super) mod api;
use api::*;
pub use api::{OwnedReadHalf, OwnedWriteHalf, ReadHalf, ReuniteError, WriteHalf};

mod interest;
use interest::*;

use super::IOContext;

pub(crate) struct Tcp {
    pub config: TcpConfig,
    pub binds: FxHashMap<Fd, ListenerHandle>,
    pub streams: FxHashMap<Fd, TransmissionControlBlock>,
}

#[derive(Debug)]
pub(crate) struct TransmissionControlBlock {
    // # General
    pub(crate) state: TcpState,
    local_addr: SocketAddr,
    peer_addr: SocketAddr,
    dropped: bool,
    span: Span,

    // # Handshake
    syn_resend_counter: usize,

    rtt_probe: SimTime,
    rtt_probe_seq_no: u32,
    rto: f64,
    srtt: f64,
    rttvar: f64,

    // # Send buffer
    tx_state: TcpSenderState, // teh senders state, to detect from API without much logic
    tx_buffer: TcpBuffer,     // the senders buffer
    tx_queue: VecDeque<IpPacket>, // a queue that prepends the interface queue, to ensure packets are send safly
    tx_last_ack_no: u32,          // the biggest ack_no recevied by an ACK
    tx_next_send_seq_no: u32, // the sequence number (byte-id) of the next data packets first byte
    tx_next_send_buffer_seq_no: u32, // the sequence number (byte-id) after the newest byte in the tx buf
    tx_max_send_seq_no: u32, // the maximum byte that may be sent, based on the flow-control window
    tx_dup_ack_counter: u32,
    tx_write_interests: Vec<TcpInterestGuard>,

    // # Recv buffer
    rx_state: TcpReceiverState,
    rx_buffer: TcpBuffer,
    rx_last_recv_seq_no: u32,
    rx_fin_seq_no: u32,
    rx_read_interests: Vec<TcpInterestGuard>,

    // # Congestions
    congestion_ctrl: bool,
    congestion_window: u32,
    ssthresh: u32,
    congestion_avoid_counter: u32,
    slow_start: bool,

    // # Parameters
    timeout: Duration,
    timewait: Duration,
    timer: u16,
    fd: Fd,
    inital_seq_no: u32,
    mss: u16,
    ttl: u8,

    // # Metrics
    sender_send_bytes: usize,
    sender_ack_bytes: usize,

    debug: bool,

    // # Interest
    established: Option<oneshot::Sender<Result<()>>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum TcpSenderState {
    Opening,       // syn
    Established,   // no close ind
    WaitForStream, // close called, fin not send
    Closing,       // fin send not acked
    Closed,        // finack
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum TcpReceiverState {
    Opening,            // syn
    Established,        // no close ind
    FinRecvWaitForData, // close called, fin not send
    Closed,             // fin send not acked
}

impl Tcp {
    pub fn new() -> Tcp {
        Tcp {
            config: TcpConfig::default(),
            binds: FxHashMap::with_hasher(FxBuildHasher::default()),
            streams: FxHashMap::with_hasher(FxBuildHasher::default()),
        }
    }
}

impl TransmissionControlBlock {
    pub fn new(fd: Fd, addr: SocketAddr, config: TcpSocketConfig) -> Self {
        let peer = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0));
        let span = tracing::span!(Level::INFO, "stream", local = Empty, peer = Empty);

        Self {
            state: TcpState::Closed,
            dropped: false,
            local_addr: addr,
            peer_addr: peer,
            span,

            syn_resend_counter: 0,

            rtt_probe: SimTime::ZERO,
            rtt_probe_seq_no: 0,
            rto: 1.0,
            srtt: 1.0,
            rttvar: 0.0,

            tx_state: TcpSenderState::Closed,
            tx_buffer: TcpBuffer::new(config.tx_buffer_size as usize, 0),
            tx_queue: VecDeque::new(),
            tx_last_ack_no: 0,
            tx_next_send_seq_no: 0,
            tx_next_send_buffer_seq_no: 0,
            tx_max_send_seq_no: 0,
            tx_dup_ack_counter: 0,
            tx_write_interests: Vec::new(),

            rx_state: TcpReceiverState::Closed,
            rx_buffer: TcpBuffer::new(config.tx_buffer_size as usize, 0),
            rx_last_recv_seq_no: 0,
            rx_fin_seq_no: 0,
            rx_read_interests: Vec::new(),

            congestion_ctrl: config.cong_ctrl,
            congestion_window: config.mss as u32,
            ssthresh: 8 * config.mss as u32,
            congestion_avoid_counter: 0,
            slow_start: true,

            timeout: Duration::from_secs(1),
            timewait: Duration::from_secs(1),
            timer: 0,
            fd,
            inital_seq_no: config.inital_seq_no,
            mss: config.mss,
            ttl: config.ttl as u8,

            sender_send_bytes: 0,
            sender_ack_bytes: 0,

            debug: config.debug,

            established: None,
        }
    }
}

fn is_valid_dest_for(socket_addr: &SocketAddr, packet_addr: &SocketAddr) -> bool {
    if socket_addr.ip().is_unspecified() {
        return socket_addr.port() == packet_addr.port();
    }

    match packet_addr {
        SocketAddr::V4(addrv4) => socket_addr == packet_addr,
        SocketAddr::V6(_) => socket_addr == packet_addr,
    }
}

impl IOContext {
    // Entry points to apply a SPAN to
    // - capture_pkt
    // - icmp_err
    // - timeout
    // - syscall for close and stuff
    // - link update
    // - read, write, peek

    pub(super) fn capture_tcp_packet(&mut self, ip_packet: IpPacketRef, ifid: IfId) -> bool {
        assert!(ip_packet.tos() == PROTO_TCP);

        let Ok(tcp_pkt) = TcpPacket::from_slice(ip_packet.content()) else {
            tracing::error!("received ip-packet with proto=0x06 (tcp) but content was no tcp-packet");
            return false;
        };

        let src = SocketAddr::new(ip_packet.src(), tcp_pkt.src_port);
        let dest = SocketAddr::new(ip_packet.dest(), tcp_pkt.dest_port);

        // (0) All sockets that are bound to the correct destination (local) address
        let mut valid_sockets = self
            .sockets
            .iter_mut()
            .filter(|(_, sock)| {
                sock.typ == SocketType::SOCK_STREAM && is_valid_dest_for(&sock.addr, &dest)
            })
            .collect::<Vec<_>>();

        // (1) Check whether its address to a stream socket pair
        if let Some((fd, sock)) = valid_sockets.iter_mut().find(|v| v.1.peer == src) {
            // (1) Active stream socket
            if !sock.interface.contains(&ifid) {
                tracing::error!("interface missmatch");
                return false;
            }

            sock.recv_q += tcp_pkt.content.len();

            let Some(mng) = self.tcp.streams.get_mut(fd) else {
                tracing::error!("found tcp socket, but missing tcp manager");
                return false;
            };

            let fd = **fd;
            self.process_packet(fd, ip_packet, tcp_pkt);

            return true;
        }

        // ONLY SYN
        if !tcp_pkt.flags.syn || tcp_pkt.flags.ack {
            return true;
        }

        // (2) Check for active listeners
        if let Some((fd, sock)) = valid_sockets
            .iter()
            .find(|(_, s)| s.peer.ip().is_unspecified() && s.peer.port() == 0)
        {
            if !sock.interface.contains(&ifid) {
                tracing::error!("interface missmatch");
                return false;
            }

            let fd = **fd;
            return self.tcp_handle_incoming_connection(src, dest, fd, ip_packet, tcp_pkt);
        }

        // (2) No active stream socket, maybe listen socket is possible
        if self.tcp.config.rst_on_syn {
            tracing::trace!("invalid incoming connection, sending RST");

            let rst = TcpPacket::rst_for_syn(&tcp_pkt);
            let rst = ip_packet.response(rst.to_buffer().unwrap());
            self.send_ip_packet(SocketIfaceBinding::Bound(ifid), rst, true);
            true
        } else {
            false
        }
    }

    pub(super) fn tcp_icmp_destination_unreachable(&mut self, fd: Fd, e: Error) {
        self.syscall(fd, TcpSyscall::DestinationUnreachable(e))
    }

    pub(crate) fn tcp_timeout(&mut self, fd: Fd, msg: Message) {
        self.process_timeout(fd, msg)
    }

    pub(crate) fn tcp_syscall(&mut self, fd: Fd, syscall: TcpSyscall) {
        self.syscall(fd, syscall)
    }

    pub(crate) fn tcp_socket_link_update(&mut self, fd: Fd) {
        let Some(ctrl) = self.tcp.streams.get_mut(&fd) else {
            return;
        };

        let Some(socket) = self.sockets.get(&ctrl.fd) else { return };
        let Some(interface) = self.ifaces.get_mut(&socket.interface.unwrap_ifid()) else { return };

        if !interface.is_busy() {
            let Some(pkt) = ctrl.tx_queue.pop_front() else {
                return
            };
            if !ctrl.tx_queue.is_empty() {
                interface.add_write_interest(ctrl.fd);
            }

            self.send_ip_packet(socket.interface.clone(), pkt, true);
        } else {
            if !ctrl.tx_queue.is_empty() {
                interface.add_write_interest(ctrl.fd);
            }
        }
    }
}

impl IOContext {
    fn tcp_handle_incoming_connection(
        &mut self,
        src: SocketAddr,
        dest: SocketAddr,
        fd: Fd,
        ip_packet: IpPacketRef,
        tcp_pkt: TcpPacket,
    ) -> bool {
        let Some(handle) = self.tcp.binds.get_mut(&fd) else {
            tracing::error!("found tcp socket, but missing tcp listener");
            return false;
        };
        let config = handle.config.clone();
        if handle.backlog.load(Ordering::SeqCst) >= config.listen_backlog {
            return true;
        }
        handle.backlog.fetch_add(1, Ordering::SeqCst);

        let r = self.tcp_handle_incoming_connection_inner(
            src,
            dest,
            fd,
            config,
            (ip_packet.src(), ip_packet.dest(), tcp_pkt),
        );

        let stream = match r {
            Ok(val) => val,
            Err(e) => {
                let handle = self.tcp.binds.get_mut(&fd).unwrap();
                handle.tx.try_send(Err(e));
                return true;
            }
        };

        let rx = match self.tcp_await_established(stream.0.inner.fd) {
            Ok(val) => val,
            Err(e) => {
                let handle = self.tcp.binds.get_mut(&fd).unwrap();
                handle.tx.try_send(Err(e));
                return true;
            }
        };

        let handle = self.tcp.binds.get_mut(&fd).unwrap();
        handle.tx.try_send(Ok((stream.0, rx)));

        true
    }

    fn tcp_handle_incoming_connection_inner(
        &mut self,
        src: SocketAddr,
        dest: SocketAddr,
        fd: Fd,
        config: TcpSocketConfig,
        pkt: (IpAddr, IpAddr, TcpPacket),
    ) -> Result<(TcpStream, SocketAddr)> {
        let stream_socket = self.dup_socket(fd)?;
        self.bind_peer(stream_socket, src)?;

        let mut ctrl = TransmissionControlBlock::new(
            stream_socket,
            self.get_socket_addr(stream_socket)?,
            config,
        );

        {
            let mut span = ctrl.span.clone();
            let mut _g = span.entered();

            self.process_state_closed(&mut ctrl, TcpEvent::SysListen());
        }

        {
            let span = ctrl.span.clone();
            let _g = span.entered();

            self.process_state_listen(&mut ctrl, TcpEvent::Syn(pkt));
        }

        self.tcp.streams.insert(stream_socket, ctrl);
        tracing::trace!("incoming connection bound to local {}", dest);

        Ok((
            TcpStream {
                inner: Arc::new(TcpStreamInner { fd: stream_socket }),
            },
            src,
        ))
    }

    fn tcp_send_packet(&mut self, ctrl: &mut TransmissionControlBlock, ip: IpPacket) {
        if ctrl.tx_queue.len() > 32 {
            tracing::error!("clearing output queue");
            ctrl.tx_queue.clear();
        }

        ctrl.tx_queue.push_back(ip);
        let Some(socket) = self.sockets.get(&ctrl.fd) else { return };
        let Some(interface) = self.ifaces.get_mut(&socket.interface.unwrap_ifid()) else { return };

        if !interface.is_busy() {
            self.send_ip_packet(
                socket.interface.clone(),
                ctrl.tx_queue.pop_front().unwrap(),
                true,
            );
        } else {
            interface.add_write_interest(ctrl.fd);
        }
    }
}

impl IOContext {
    fn process_packet(&mut self, fd: Fd, ip: IpPacketRef<'_, '_>, pkt: TcpPacket) {
        let Some(mut ctrl) = self.tcp.streams.remove(&fd) else {
            return
        };

        let span = ctrl.span.clone();
        let _g = span.entered();

        // TODO: assertion must check validity in terms of zero binds
        // assert_eq!(ip.dest(), ctrl.local_addr.ip());
        assert_eq!(pkt.dest_port, ctrl.local_addr.port());

        // Missing PERM
        let event = if pkt.flags.rst {
            TcpEvent::Rst((ip.src(), ip.dest(), pkt))
        } else if pkt.flags.syn {
            TcpEvent::Syn((ip.src(), ip.dest(), pkt))
        } else {
            if pkt.flags.fin {
                TcpEvent::Fin((ip.src(), ip.dest(), pkt))
            } else {
                if pkt.content.is_empty() && pkt.flags.ack {
                    TcpEvent::Ack((ip.src(), ip.dest(), pkt))
                } else {
                    TcpEvent::Data((ip.src(), ip.dest(), pkt))
                }
            }
        };

        match ctrl.state {
            TcpState::Closed => self.process_state_closed(&mut ctrl, event),
            TcpState::Listen => self.process_state_listen(&mut ctrl, event),
            TcpState::SynSent => self.process_state_syn_sent(&mut ctrl, event),
            TcpState::SynRcvd => self.process_state_syn_rcvd(&mut ctrl, event),
            TcpState::Established => self.process_state_established(&mut ctrl, event),
            TcpState::FinWait1 => self.process_state_fin_wait1(&mut ctrl, event),
            TcpState::FinWait2 => self.process_state_fin_wait2(&mut ctrl, event),
            TcpState::TimeWait => self.process_state_time_wait(&mut ctrl, event),
            TcpState::Closing => self.process_state_closing(&mut ctrl, event),
            TcpState::CloseWait => self.process_state_close_wait(&mut ctrl, event),
            TcpState::LastAck => self.process_state_last_ack(&mut ctrl, event),
        }

        self.return_ctrl(fd, ctrl);
    }

    fn process_timeout(&mut self, fd: Fd, msg: Message) {
        let Some(mut ctrl) = self.tcp.streams.remove(&fd) else {
            return
        };

        let span = ctrl.span.clone();
        let _g = span.entered();

        // TODO: this extra if should not be nessecary
        // if ctrl.state != TcpState::TimeWait {
        if msg.header().id != ctrl.timer {
            self.tcp.streams.insert(fd, ctrl);
            return;
        }
        // }

        let event = TcpEvent::Timeout();
        match ctrl.state {
            TcpState::Closed => self.process_state_closed(&mut ctrl, event),
            TcpState::Listen => self.process_state_listen(&mut ctrl, event),
            TcpState::SynSent => self.process_state_syn_sent(&mut ctrl, event),
            TcpState::SynRcvd => self.process_state_syn_rcvd(&mut ctrl, event),
            TcpState::Established => self.process_state_established(&mut ctrl, event),
            TcpState::FinWait1 => self.process_state_fin_wait1(&mut ctrl, event),
            TcpState::FinWait2 => self.process_state_fin_wait2(&mut ctrl, event),
            TcpState::TimeWait => self.process_state_time_wait(&mut ctrl, event),
            TcpState::Closing => self.process_state_closing(&mut ctrl, event),
            TcpState::CloseWait => self.process_state_close_wait(&mut ctrl, event),
            TcpState::LastAck => self.process_state_last_ack(&mut ctrl, event),
        }

        self.return_ctrl(fd, ctrl)
    }

    fn syscall(&mut self, fd: Fd, syscall: TcpSyscall) {
        let Some(mut ctrl) = self.tcp.streams.remove(&fd) else {
            return
        };

        let span = ctrl.span.clone();
        let _g = span.entered();

        let event = match syscall {
            TcpSyscall::Listen() => TcpEvent::SysListen(),
            TcpSyscall::Open(peer) => TcpEvent::SysOpen(peer),
            TcpSyscall::Close() => {
                ctrl.dropped = true;
                TcpEvent::SysClose()
            }

            TcpSyscall::DestinationUnreachable(e) => {
                ctrl.dropped = true;
                TcpEvent::DestinationUnreachable(e)
            }
        };

        match ctrl.state {
            TcpState::Closed => self.process_state_closed(&mut ctrl, event),
            TcpState::Listen => self.process_state_listen(&mut ctrl, event),
            TcpState::SynSent => self.process_state_syn_sent(&mut ctrl, event),
            TcpState::SynRcvd => self.process_state_syn_rcvd(&mut ctrl, event),
            TcpState::Established => self.process_state_established(&mut ctrl, event),
            TcpState::FinWait1 => self.process_state_fin_wait1(&mut ctrl, event),
            TcpState::FinWait2 => self.process_state_fin_wait2(&mut ctrl, event),
            TcpState::TimeWait => self.process_state_time_wait(&mut ctrl, event),
            TcpState::Closing => self.process_state_closing(&mut ctrl, event),
            TcpState::CloseWait => self.process_state_close_wait(&mut ctrl, event),
            TcpState::LastAck => self.process_state_last_ack(&mut ctrl, event),
        }

        self.return_ctrl(fd, ctrl)
    }

    fn return_ctrl(&mut self, fd: Fd, mut ctrl: TransmissionControlBlock) {
        if ctrl.state == TcpState::Closed && ctrl.dropped {
            tracing::trace!("dropping socket");

            // if ctrl.debug {
            //     ctrl.debug_cong_window.finish();

            //     ctrl.debug_ssthresh.collect(ctrl.ssthresh as f64);
            //     ctrl.debug_ssthresh.finish();

            //     ctrl.debug_rto.collect(ctrl.rto as f64);
            //     ctrl.debug_rto.finish();
            // }
            self.close_socket(fd);
        } else {
            self.tcp.streams.insert(fd, ctrl);
        }
    }

    //

    #[instrument(level = "trace", name = "tcp_closed", skip_all)]
    fn process_state_closed(&mut self, ctrl: &mut TransmissionControlBlock, event: TcpEvent) {
        match event {
            TcpEvent::SysListen() => {
                // ctrl.span = tracing::span!(Level::INFO, "listener", port = ctrl.local_addr.port());
                ctrl.span.record("local", debug(ctrl.local_addr));
                ctrl.state = TcpState::Listen;
                // syscall reply
            }
            TcpEvent::SysOpen(peer) => {
                ctrl.peer_addr = peer;
                // ctrl.span = tracing::span!(Level::INFO, "stream", local=?ctrl.local_addr, ?peer);
                ctrl.span.record("local", debug(ctrl.local_addr));
                ctrl.span.record("peer", debug(ctrl.peer_addr));

                self.bind_peer(ctrl.fd, peer);

                ctrl.tx_state = TcpSenderState::Opening;
                ctrl.rx_state = TcpReceiverState::Opening;

                ctrl.syn_resend_counter = 0;
                ctrl.rx_last_recv_seq_no = 0;
                ctrl.tx_next_send_seq_no = ctrl.inital_seq_no;
                ctrl.tx_buffer.bump(ctrl.tx_next_send_seq_no + 1);
                // ctrl.next_send_buffer_seq_no = self.next_send_seq_no + 1; TODO
                ctrl.tx_max_send_seq_no = ctrl.tx_next_send_seq_no;

                let mut pkt = ctrl.create_packet(TcpPacketId::Syn, ctrl.tx_next_send_seq_no, 0);
                pkt.options = ctrl.syn_options();
                ctrl.tx_next_send_seq_no += 1;

                pkt.window = ctrl.recv_window();

                tracing::trace!("Sending SYN {{ seq_no: {} }}", pkt.seq_no);
                ctrl.rtt_probe = SimTime::now();
                self.tcp_send_packet(ctrl, ctrl.ip_packet_for(pkt));

                ctrl.set_timer(ctrl.timeout);

                ctrl.state = TcpState::SynSent;
                // syscall reply
            }
            TcpEvent::SysClose() => {}
            _ => unimplemented!(),
        }
    }

    #[instrument(level = "trace", name = "tcp_listen", skip_all)]
    fn process_state_listen(&mut self, ctrl: &mut TransmissionControlBlock, event: TcpEvent) {
        match event {
            TcpEvent::Syn((src, dest, syn)) => {
                assert!(syn.flags.syn);

                ctrl.peer_addr = SocketAddr::new(src, syn.src_port);
                // ctrl.span = tracing::span!(Level::INFO, "stream", local=?ctrl.local_addr, peer=?ctrl.peer_addr);
                ctrl.span.record("local", debug(ctrl.local_addr));
                ctrl.span.record("peer", debug(ctrl.peer_addr));

                ctrl.rx_last_recv_seq_no = syn.seq_no;
                ctrl.rx_buffer.bump(syn.seq_no + 1);

                ctrl.tx_next_send_seq_no = ctrl.inital_seq_no;

                ctrl.tx_buffer.bump(ctrl.tx_next_send_seq_no + 1);

                ctrl.tx_next_send_buffer_seq_no = ctrl.tx_next_send_seq_no + 1;
                ctrl.tx_max_send_seq_no = ctrl.tx_next_send_seq_no + syn.window as u32;
                ctrl.apply_syn_options(&syn.options);

                let mut pkt = ctrl.create_packet(
                    TcpPacketId::Syn,
                    ctrl.tx_next_send_seq_no,
                    ctrl.rx_last_recv_seq_no + 1,
                );
                pkt.options = ctrl.syn_options();
                pkt.window = ctrl.recv_window();
                ctrl.tx_next_send_seq_no += 1;

                tracing::trace!(
                    "got SYN from {}, sending SYNACK {{ seq_no: {}, ack: {} }}",
                    ctrl.peer_addr,
                    pkt.seq_no,
                    pkt.ack_no
                );
                ctrl.rtt_probe = SimTime::now();
                self.tcp_send_packet(ctrl, ctrl.ip_packet_for(pkt));
                ctrl.set_timer(ctrl.timeout);

                // syscall incoming ind.
                ctrl.state = TcpState::SynRcvd;
            }
            TcpEvent::SysClose() => {
                ctrl.state = TcpState::Closed;
                // syscall reply
            }
            _ => unimplemented!("Got: {:?}", event),
        }
    }

    #[instrument(level = "trace", name = "tcp_syn_sent", skip_all)]
    fn process_state_syn_sent(&mut self, ctrl: &mut TransmissionControlBlock, event: TcpEvent) {
        match event {
            TcpEvent::Syn((src, dest, pkt)) => {
                ctrl.rx_last_recv_seq_no = pkt.seq_no;
                ctrl.rx_buffer.bump(pkt.seq_no + 1);
                ctrl.apply_syn_options(&pkt.options);

                if pkt.flags.ack {
                    ctrl.tx_last_ack_no = pkt.ack_no;
                    ctrl.tx_next_send_buffer_seq_no = ctrl.tx_next_send_seq_no;
                    ctrl.tx_max_send_seq_no = pkt.ack_no + pkt.window as u32; //

                    self.send_ack(ctrl, ctrl.rx_last_recv_seq_no + 1, ctrl.recv_window());

                    ctrl.cancel_timer();
                    // syscall established ind

                    let rtt = SimTime::now() - ctrl.rtt_probe;
                    ctrl.timeout = Duration::from_secs_f64(rtt.as_secs_f64() * 4.0);
                    ctrl.add_inital_rtt_sample(rtt.as_secs_f64());
                    ctrl.rtt_probe = SimTime::MAX;

                    ctrl.tx_state = TcpSenderState::Established;
                    ctrl.rx_state = TcpReceiverState::Established;

                    // ctrl.debug_cong_window
                    //     .collect(ctrl.congestion_window as f64);
                    // ctrl.debug_ssthresh.collect(ctrl.ssthresh as f64);

                    tracing::trace!(
                        "established with Sender {{ seq_no: {}, win: {}, rtt: {:?} }} and Receiver {{ next_expected: {} }}",
                        ctrl.tx_next_send_seq_no,
                        ctrl.send_window(),
                        ctrl.rto,
                        ctrl.rx_last_recv_seq_no
                    );
                    ctrl.state = TcpState::Established;
                    ctrl.established.take().map(|v| v.send(Ok(())));
                } else {
                    tracing::trace!("simultaneous handshake, transition to tcp::synrecv");

                    self.send_ack(ctrl, ctrl.rx_last_recv_seq_no + 1, ctrl.recv_window());
                    ctrl.tx_max_send_seq_no = ctrl.tx_last_ack_no + pkt.window as u32;
                    ctrl.tx_next_send_buffer_seq_no = ctrl.tx_next_send_seq_no;
                    ctrl.state = TcpState::SynRcvd;
                }
            }
            TcpEvent::Ack(_) => {
                // NOP
            }
            TcpEvent::Timeout() => {
                ctrl.syn_resend_counter += 1;
                if ctrl.syn_resend_counter >= 3 {
                    // Do Somthing
                    ctrl.established.take().map(|v| {
                        v.send(Err(Error::new(
                            ErrorKind::ConnectionRefused,
                            "host unreachable",
                        )));
                    });
                    ctrl.state = TcpState::Closed;
                    return;
                }

                let pkt = ctrl.create_packet(TcpPacketId::Syn, ctrl.tx_next_send_seq_no - 1, 0);
                tracing::trace!("retransmitting SYN {{ seq_no: {} }}", pkt.seq_no);
                self.tcp_send_packet(ctrl, ctrl.ip_packet_for(pkt));
                ctrl.set_timer(ctrl.timeout);
            }
            TcpEvent::Rst((_, _, pkt)) => {
                // Port is not reachable
                assert_eq!(pkt.ack_no + 1, ctrl.tx_next_send_seq_no);
                tracing::trace!("aborting due to port unreachabele (RST)");

                ctrl.established.take().map(|v| {
                    v.send(Err(Error::new(
                        ErrorKind::ConnectionRefused,
                        "port unreachable",
                    )))
                });
                ctrl.cancel_timer();
                ctrl.state == TcpState::Closed;
            }
            TcpEvent::DestinationUnreachable(e) => {
                // Port is not reachable
                tracing::trace!("aborting due to destination unreachabele (ICMP)");

                ctrl.established.take().map(|v| v.send(Err(e)));
                ctrl.cancel_timer();
                ctrl.state == TcpState::Closed;
            }
            TcpEvent::SysClose() => {
                ctrl.state = TcpState::Closed;
            }
            _ => unimplemented!("{:?}", event),
        }
    }

    #[instrument(level = "trace", name = "tcp_syn_rcvd", skip_all)]
    fn process_state_syn_rcvd(&mut self, ctrl: &mut TransmissionControlBlock, event: TcpEvent) {
        match event {
            TcpEvent::Syn(_) => (),
            TcpEvent::Fin(_) => (),
            TcpEvent::Data((src, dest, pkt)) | TcpEvent::Ack((src, dest, pkt)) => {
                // Own addition
                ctrl.tx_last_ack_no = pkt.ack_no;

                if ctrl.tx_last_ack_no + pkt.window as u32 - 1 > ctrl.tx_max_send_seq_no {
                    ctrl.tx_max_send_seq_no = pkt.ack_no + pkt.window as u32;
                }

                ctrl.cancel_timer();

                let rtt = SimTime::now() - ctrl.rtt_probe;
                ctrl.timeout = Duration::from_secs_f64(rtt.as_secs_f64() * 4.0);
                ctrl.add_inital_rtt_sample(rtt.as_secs_f64());
                ctrl.rtt_probe = SimTime::MAX;

                // syscall estab ind
                ctrl.tx_state = TcpSenderState::Established;
                ctrl.rx_state = TcpReceiverState::Established;

                // ctrl.debug_cong_window
                //     .collect(ctrl.congestion_window as f64);
                // ctrl.debug_ssthresh.collect(ctrl.ssthresh as f64);

                tracing::trace!(
                    "established with Sender {{ seq_no: {}, win: {}, rtt: {:?} }} and Receiver {{ next_expected: {} }}",
                    ctrl.tx_next_send_seq_no,
                    ctrl.send_window(),
                    ctrl.rto,
                    ctrl.rx_last_recv_seq_no
                );

                ctrl.state = TcpState::Established;
                ctrl.established.take().map(|v| v.send(Ok(())));

                self.handle_data(ctrl, src, dest, pkt)
            }
            TcpEvent::Timeout() => {
                let mut pkt = ctrl.create_packet(
                    TcpPacketId::Syn,
                    ctrl.tx_next_send_seq_no - 1,
                    ctrl.rx_last_recv_seq_no + 1,
                );
                pkt.window = ctrl.recv_window();

                ctrl.syn_resend_counter += 1;
                if ctrl.syn_resend_counter >= 3 {
                    // Do Somthing
                    ctrl.established.take().map(|v| {
                        v.send(Err(Error::new(
                            ErrorKind::ConnectionRefused,
                            "host unreachable",
                        )));
                    });
                    ctrl.state = TcpState::Closed;
                    return;
                }

                tracing::trace!(
                    "retransmitting SYNACK {{ seq_no: {}, ack_no: {} }}",
                    pkt.seq_no,
                    pkt.ack_no
                );

                self.tcp_send_packet(ctrl, ctrl.ip_packet_for(pkt));

                ctrl.set_timer(ctrl.timeout);
            }
            TcpEvent::Rst((_, _, pkt)) => {
                // Unknown RST
                assert_eq!(pkt.ack_no + 1, ctrl.tx_next_send_seq_no);
                tracing::trace!("aborting due to unknown reason (RST)");

                ctrl.established.take().map(|v| {
                    v.send(Err(Error::new(
                        ErrorKind::ConnectionRefused,
                        "port unreachable",
                    )))
                });
                ctrl.cancel_timer();
                ctrl.state == TcpState::Closed;
            }
            TcpEvent::SysClose() => {
                ctrl.state = TcpState::Closed;
            }
            _ => unimplemented!("{:?}", event),
        }
    }

    #[instrument(level = "trace", name = "tcp_established", skip_all)]
    fn process_state_established(&mut self, ctrl: &mut TransmissionControlBlock, event: TcpEvent) {
        match event {
            TcpEvent::SysClose() => {
                // Handle dropped
                // Active close - consider self client
                // -> self will not read from the recv_buffer any longer
                // -> self must still ack the data send by the server, but no more windows
                // -> self may posses data in the send buffer that must still be send.
                tracing::trace!("declaring local closing intention");

                // (0) Declere closing intention
                ctrl.tx_state = TcpSenderState::WaitForStream;

                // (1) If stream is allready ready go on
                self.do_sending(ctrl)
            }
            TcpEvent::Fin((src, dest, pkt)) => {
                // Peer initated close
                // Responsder close - consider self server
                // -> Peer will no longer receive data
                // -> Peer may still send data

                if ctrl.rx_last_recv_seq_no + 1 == pkt.seq_no {
                    // (0) Handle last ack from FINACK packet
                    tracing::trace!("got FIN #{}, responding immidiatly", pkt.seq_no);
                    ctrl.rx_last_recv_seq_no = pkt.seq_no;
                    self.handle_data(ctrl, src, dest, pkt);

                    // (1) Acknowledge FIN
                    self.send_ack(ctrl, ctrl.rx_last_recv_seq_no + 1, ctrl.recv_window());
                    ctrl.state = TcpState::CloseWait;

                    // (2) Own FIN means that recv buffer will no longer be used
                    // -> Wake all interest so that they can fail with 0
                    ctrl.rx_read_interests.drain(..).for_each(|g| g.wake());

                    // (3) Skip staet
                    ctrl.rx_state = TcpReceiverState::Closed;
                } else {
                    tracing::error!(
                        "got FIN #{}, but missing {} data-bytes",
                        pkt.seq_no,
                        pkt.seq_no - (ctrl.rx_last_recv_seq_no + 1)
                    );
                    ctrl.rx_state = TcpReceiverState::FinRecvWaitForData;
                    ctrl.rx_fin_seq_no = pkt.seq_no;

                    // self.handle_data(ctrl, src, dest, pkt);
                }
            }
            TcpEvent::Ack((src, dest, pkt))
            | TcpEvent::Data((src, dest, pkt))
            | TcpEvent::Perm((src, dest, pkt)) => {
                self.handle_data(ctrl, src, dest, pkt);
            }
            TcpEvent::Timeout() => {
                self.handle_data_timeout(ctrl);
            }
            TcpEvent::SysSend() | TcpEvent::SysRecv() => todo!(),

            // Own addition
            TcpEvent::Syn(_) => {
                // This is client and the ACK must have been dropped.
            }

            _ => {
                panic!("Rejecting {:?}", event)
            }
        }
    }

    #[instrument(level = "trace", name = "tcp_fin_wait_1", skip_all)]
    fn process_state_fin_wait1(&mut self, ctrl: &mut TransmissionControlBlock, event: TcpEvent) {
        // Consider self client
        match event {
            TcpEvent::Fin((src, dest, pkt)) => {
                // Got FIN from server before ACK of FIN
                // Simultaneous Close
                // -> Both sides will no longer receive data
                // -> Both sides may try to send data, can be ignored

                // (0) Handle last ACK from FINACK
                tracing::trace!("received FIN, simultaneous close, transition to closing");
                ctrl.rx_last_recv_seq_no = pkt.seq_no;
                if pkt.flags.ack {
                    self.handle_data(ctrl, src, dest, pkt);
                }

                // (1) Acknowledge FIN (peer will do the same)
                self.send_ack(ctrl, ctrl.rx_last_recv_seq_no + 1, ctrl.recv_window());

                // (2) Wait for peer FIN acknowledge
                ctrl.state = TcpState::Closing;
            }
            TcpEvent::Timeout() => {
                // self is client - so data may need to be send before close.
                self.handle_data_timeout(ctrl)
            }
            TcpEvent::Data((src, dest, pkt))
            | TcpEvent::Ack((src, dest, pkt))
            | TcpEvent::Perm((src, dest, pkt)) => {
                // Got ACK from server
                // -> may be data packet, could be ingored
                // -> may be ack of data packet, handle
                // -> may be ACK of FIN

                // tracing::trace!( "{} {}", pkt.ack_no, ctrl.sender_next_send_seq_no);

                // (0) Check for ACK of FIN (seq_no = nss + 1)
                let ack_of_fin = pkt.flags.ack && pkt.ack_no == ctrl.tx_next_send_seq_no;
                if ack_of_fin {
                    // (1) Switch to finwait2 to prevent simultaneous close
                    // -> Since ACK of FIN was send before FIN peer must be in estab
                    // thus now close_wait
                    tracing::trace!("got ACK of FIN #{}", pkt.ack_no);
                    ctrl.state = TcpState::FinWait2;
                } else {
                    self.handle_data(ctrl, src, dest, pkt);
                }
            }
            TcpEvent::SysRecv() => {
                unimplemented!()
            }
            _ => unimplemented!("{event:?}"),
        }
    }

    #[instrument(level = "trace", name = "tcp_fin_wait_2", skip_all)]
    fn process_state_fin_wait2(&mut self, ctrl: &mut TransmissionControlBlock, event: TcpEvent) {
        // consider self client
        // consider non-simultaneous close
        match event {
            TcpEvent::Fin((src, dest, pkt)) => {
                // Active close
                // Wait for FIN indicating that server has decided to close.

                // (0) Handle last ACK of FINACK
                tracing::trace!("got FIN #{}, going to time-wait", pkt.seq_no);
                ctrl.rx_last_recv_seq_no = pkt.seq_no;

                // (1) Send ACK for FIN
                self.send_ack(ctrl, pkt.seq_no + 1, ctrl.recv_window());
                ctrl.set_timer(ctrl.timewait);

                // (2) Switch to Time-Wait to handle timeouts for final ACKs
                ctrl.state = TcpState::TimeWait;
            }
            TcpEvent::Timeout() => self.handle_data_timeout(ctrl),
            TcpEvent::Data((src, dest, pkt))
            | TcpEvent::Ack((src, dest, pkt))
            | TcpEvent::Perm((src, dest, pkt)) => {
                // Since server has not yet been closed, data may be send
                self.handle_data(ctrl, src, dest, pkt)
            }
            TcpEvent::SysRecv() => unimplemented!(),
            _ => unimplemented!(),
        }
    }

    #[instrument(level = "trace", name = "tcp_closing", skip_all)]
    fn process_state_closing(&mut self, ctrl: &mut TransmissionControlBlock, event: TcpEvent) {
        // consider self client or server (both client believe)
        // both parties send FIN, expect ACK
        match event {
            TcpEvent::Timeout() => {
                // Both parties closed -> no data
                // -> but ack resend may be nessecary
                self.handle_data_timeout(ctrl)
            }
            TcpEvent::Ack((src, dest, pkt)) | TcpEvent::Perm((src, dest, pkt)) => {
                // (0) Ignore data parts of packets --> no need for receivers

                // (1) Check for ACK of FIN
                let ack_of_fin = pkt.flags.ack && ctrl.tx_next_send_seq_no == pkt.ack_no;
                if ack_of_fin {
                    tracing::trace!("got ACK of FIN {}, transitioning to time_wait", pkt.ack_no);
                    // (2) Switch to time_wait
                    ctrl.set_timer(ctrl.timewait);
                    ctrl.state = TcpState::TimeWait;
                }
            }
            TcpEvent::SysRecv() => unimplemented!(),
            TcpEvent::SysOpen(_) | TcpEvent::SysListen() => unimplemented!(),
            _ => unimplemented!(),
        }
    }

    #[instrument(level = "trace", name = "tcp_time_wait", skip_all)]
    fn process_state_time_wait(&mut self, ctrl: &mut TransmissionControlBlock, event: TcpEvent) {
        // consider self client or at least client believe
        // assume either LAST ACK or LAST FIN was allready send
        match event {
            TcpEvent::Timeout() => {
                // After waiting for errors ensure close the socket.
                ctrl.reset_connection_pars();
                tracing::trace!("Closed");
                ctrl.state = TcpState::Closed;
            }
            TcpEvent::Fin((_, _, fin)) => {
                // we are client
                // resent FIN, thus ACKofFIN must be lost
                self.send_ack(ctrl, fin.seq_no + 1, ctrl.recv_window());
            }
            TcpEvent::SysRecv() => unimplemented!(),
            TcpEvent::SysOpen(_) | TcpEvent::SysListen() => unimplemented!(),
            TcpEvent::SysClose() => {}
            _ => todo!("unknown event :: {event:?}"),
        }
    }

    #[instrument(level = "trace", name = "tcp_close_wait", skip_all)]
    fn process_state_close_wait(&mut self, ctrl: &mut TransmissionControlBlock, event: TcpEvent) {
        // consider self server
        // client will no longer receive data, but may still send
        match event {
            TcpEvent::Timeout() => {
                // ACK resend must be handled to get to ACK of FIN
                self.handle_data_timeout(ctrl)
            }
            TcpEvent::SysClose() => {
                // Once the application agrees to close
                // send ACK of FIN

                // (0) Send own FIN
                let pkt = ctrl.create_packet(
                    TcpPacketId::Fin,
                    ctrl.tx_next_send_seq_no,
                    ctrl.rx_last_recv_seq_no,
                );
                self.tcp_send_packet(ctrl, ctrl.ip_packet_for(pkt));

                // (2) Wait for ACK
                // -> client will only send ACK as response to FIN
                ctrl.set_data_timer();
                ctrl.state = TcpState::LastAck;
            }
            TcpEvent::Fin(_) => {
                // DO nothgin
            }
            _ => unimplemented!("{event:?}"),
        }
    }

    #[instrument(level = "trace", name = "tcp_last_ack", skip_all)]
    fn process_state_last_ack(&mut self, ctrl: &mut TransmissionControlBlock, event: TcpEvent) {
        // consider self server
        match event {
            TcpEvent::Ack(_) => {
                // (0) Each last ack will be only for FIN (else simultaneous close)
                ctrl.reset_connection_pars();
                ctrl.state = TcpState::Closed;
                tracing::trace!("Closed");
            }
            TcpEvent::Fin(fin) => {
                // we are the server:
                // the ACKofFIN we send was lost, thus resent it
                self.send_ack(ctrl, ctrl.rx_fin_seq_no, ctrl.recv_window());
            }
            TcpEvent::Timeout() => {
                // we are the server:
                // our FIN was not yet acked, thus it was lost
                // resend it
                let pkt = ctrl.create_packet(
                    TcpPacketId::Fin,
                    ctrl.tx_next_send_seq_no,
                    ctrl.rx_last_recv_seq_no,
                );
                self.tcp_send_packet(ctrl, ctrl.ip_packet_for(pkt));
                ctrl.set_data_timer();
            }
            _ => todo!("unknonw event: {:?}", event),
        }
    }

    fn handle_data(
        &mut self,
        ctrl: &mut TransmissionControlBlock,
        src: IpAddr,
        dest: IpAddr,
        pkt: TcpPacket,
    ) {
        // tracing::trace!(
        //     "Data {{ acked: {}, next: {}, win: {} }} with Packet {{ seq_no: {}, ack_no: {}, data: {} }}",
        //     ctrl.tx_last_ack_no,
        //     ctrl.tx_next_send_seq_no,
        //     ctrl.send_window(),
        //     pkt.seq_no,
        //     pkt.ack_no,
        //     pkt.content.len()
        // );

        // (A) Handle acknowledgement information
        if pkt.flags.ack {
            // let buf_full = self.send_queue == self.send_buffer.size();
            let buf_full = ctrl.tx_buffer.rem() == 0;

            if ctrl.tx_last_ack_no < pkt.ack_no {
                // RX: some new databytes are being acked

                ctrl.tx_dup_ack_counter = 0;
                ctrl.cancel_timer();

                let n = pkt.ack_no - ctrl.tx_last_ack_no;
                ctrl.tx_buffer.free(n as usize);

                tracing::trace!(
                    "freeing acked data: {} bytes starting at {}",
                    n,
                    ctrl.tx_last_ack_no
                );

                if pkt.ack_no == ctrl.rtt_probe_seq_no {
                    let dur = SimTime::now() - ctrl.rtt_probe;
                    ctrl.add_rtt_sample(dur.as_secs_f64());

                    ctrl.rtt_probe_seq_no = 0;
                    ctrl.rtt_probe = SimTime::MAX;
                } else if pkt.ack_no > ctrl.rtt_probe_seq_no {
                    // rtt unsound
                    ctrl.rtt_probe_seq_no = 0;
                    ctrl.rtt_probe = SimTime::MAX;
                }

                // freeBuffers
                ctrl.tx_last_ack_no = pkt.ack_no;

                if ctrl.tx_last_ack_no < ctrl.tx_next_send_seq_no {
                    ctrl.set_data_timer()
                } else {
                    // opti
                    ctrl.tx_next_send_seq_no = ctrl.tx_last_ack_no;
                }

                if ctrl.congestion_ctrl {
                    if ctrl.congestion_window < ctrl.ssthresh {
                        // Slow start
                        ctrl.congestion_window += ctrl.mss as u32;
                        ctrl.congestion_avoid_counter = ctrl.congestion_window;

                        // ctrl.debug_cong_window
                        //     .collect(ctrl.congestion_window as f64);
                    } else {
                        // AIMD
                        ctrl.congestion_avoid_counter =
                            ctrl.congestion_avoid_counter.saturating_sub(n as u32);
                        if ctrl.congestion_avoid_counter == 0 {
                            ctrl.congestion_window += ctrl.mss as u32;
                            // FIXME: custom addition may be a bad idea but we will see.
                            ctrl.congestion_window = ctrl.congestion_window.min(ctrl.send_window());
                            ctrl.congestion_avoid_counter = ctrl.congestion_window;
                        }

                        // ctrl.debug_cong_window
                        //     .collect(ctrl.congestion_window as f64);
                    }
                }

                if buf_full {
                    // SysStopInd
                }

                // Wakeup write interests
                ctrl.tx_write_interests.drain(..).for_each(|g| g.wake())
            } else {
                // RX: we recevived an ACK with the same info allready
                // - either multiple acks were send, bc missing data segemnt
                // - or multiple ACKs indicate other changes, like window updats

                let is_win_update = ctrl.tx_max_send_seq_no != pkt.ack_no + pkt.window as u32;

                if pkt.ack_no == ctrl.tx_last_ack_no
                    && pkt.ack_no < ctrl.tx_next_send_seq_no
                    && !is_win_update
                {
                    if ctrl.tx_dup_ack_counter == 2 {
                        tracing::error!("received duplicated ack, resetting to {}", pkt.ack_no);
                        // resent this packet specificly
                        ctrl.congestion_window += ctrl.congestion_window / 2;
                        self.handle_data_timeout(ctrl);
                        ctrl.tx_dup_ack_counter = 0;
                    } else {
                        ctrl.tx_dup_ack_counter += 1;
                    }
                }
            }

            ctrl.tx_max_send_seq_no = pkt.ack_no + pkt.window as u32;
            self.do_sending(ctrl);
        }

        // (B) Handle data part
        if !pkt.content.is_empty() {
            if pkt.seq_no != ctrl.rx_last_recv_seq_no + 1 {
                tracing::warn!(
                    "got out of order packet seq_no: {} with {} bytes (expected {})",
                    pkt.seq_no,
                    pkt.content.len(),
                    ctrl.rx_last_recv_seq_no + 1,
                );
                // if ctrl.rx_dup_ack_counter < 1 {
                self.send_ack(ctrl, ctrl.rx_last_recv_seq_no + 1, ctrl.recv_window());
                // }

                // FIXME: if NACK is implemented, dont do that
                return;
            }

            tracing::trace!(
                "received {} bytes starting at {}",
                pkt.content.len(),
                pkt.seq_no
            );
            // ctrl.receiver_buffer.state();

            // (0) Capture the length of the readable slice before the incoming packet
            let prev = ctrl.rx_buffer.len_continous();

            // (1) Insert the packet into the receiver_buffer
            let n = ctrl.rx_buffer.write(&pkt.content, pkt.seq_no);
            ctrl.rx_last_recv_seq_no = pkt.seq_no + pkt.content.len() as u32 - 1;

            // TODO:
            assert_eq!(
                n,
                pkt.content.len(),
                "Could not write received packet into buffer"
            );

            // (2) If the readable slice has increased, new read interest may be fulfilled
            // so wake up corresponding guards.
            let next = ctrl.rx_buffer.len_continous();
            if next > prev {
                ctrl.rx_read_interests.drain(..).for_each(|g| g.wake());
            }

            // (3) Acknowledge the data that was send
            self.send_ack(ctrl, ctrl.rx_last_recv_seq_no + 1, ctrl.recv_window());

            // ctrl.receiver_buffer.state();

            // (4) If we are in queue to send a FINACK check for the finack
            if ctrl.rx_state == TcpReceiverState::FinRecvWaitForData
                && ctrl.rx_last_recv_seq_no + 1 == ctrl.rx_fin_seq_no
            {
                // rx_last_recv_seq_no == SeqNo of last byte of stream
                // rx_fin_seq_no == InvalidByteSeqNo

                tracing::trace!("sending FINACK {}(+1)", ctrl.rx_fin_seq_no);
                // Send ACKOFFIN, ack Invalid FIN byte
                self.send_ack(ctrl, ctrl.rx_fin_seq_no + 1, ctrl.recv_window());
                ctrl.state = TcpState::CloseWait;

                // (2) Own FIN means that recv buffer will no longer be used
                // -> Wake all interest so that they can fail with 0
                ctrl.rx_read_interests.drain(..).for_each(|g| g.wake());

                // (3) Skip staet
                ctrl.rx_state = TcpReceiverState::Closed;
            }
        }
    }

    fn do_sending(&mut self, ctrl: &mut TransmissionControlBlock) {
        // // FIN may be send without window
        // if ctrl.sender_max_send_seq_no == ctrl.sender_next_send_seq_no.saturating_sub(2) && true {
        //     ctrl.sender_max_send_seq_no += 1;
        // }

        let max_seq_no = if ctrl.congestion_ctrl {
            ctrl.tx_max_send_seq_no
                .min(ctrl.tx_last_ack_no + ctrl.congestion_window)
        } else {
            ctrl.tx_max_send_seq_no
        };

        // Try sending data as long as:
        // a) Data is allowed to be send according to the minimal window
        // b) There is data to send in the sender_buffer

        while ctrl.tx_next_send_seq_no < max_seq_no
            && ctrl.tx_next_send_seq_no < ctrl.tx_next_send_buffer_seq_no
        {
            // send buffer set timeout
            // reschedule timer
            // get_data_packet
            // send

            ctrl.set_data_timer();

            // (0) Only send fragments within the remaining window and mtu limitiations
            // CHECKME: change max_seq_no - next_send to max_buf
            let size = (ctrl.mss as usize)
                .min((max_seq_no - ctrl.tx_next_send_seq_no) as usize)
                .min(ctrl.send_buffer_len() as usize);
            let mut buf = vec![0u8; size];

            // (1) Peek the data from the sender_buffer (n = size)
            let n = ctrl.tx_buffer.peek_at(&mut buf, ctrl.tx_next_send_seq_no);
            buf.truncate(n);

            if ctrl.rtt_probe == SimTime::MAX {
                // choose this packet as rtt probe
                ctrl.rtt_probe = SimTime::now();
                ctrl.rtt_probe_seq_no = ctrl.tx_next_send_seq_no + n as u32;
            }

            let is_last_sendable = ctrl.send_buffer_len() == n as u32;
            tracing::trace!(
                "sending {} bytes beginning at {}",
                n,
                ctrl.tx_next_send_seq_no,
            );

            // (2) Create a TCPData packet with the data embedded.
            let mut tcp = TcpPacket {
                src_port: ctrl.local_addr.port(),
                dest_port: ctrl.peer_addr.port(),
                seq_no: ctrl.tx_next_send_seq_no,
                ack_no: ctrl.rx_last_recv_seq_no,
                flags: TcpFlags::new().ack(true).psh(is_last_sendable),
                window: ctrl.recv_window(),
                urgent_ptr: 0,
                options: Vec::new(),
                content: buf,
            };

            // (3) Forward the packet to the socket output.
            self.tcp_send_packet(ctrl, ctrl.ip_packet_for(tcp));

            // (4) Increment the sequence number on success
            ctrl.tx_next_send_seq_no += n as u32;
        }

        if ctrl.tx_state == TcpSenderState::WaitForStream
            && ctrl.tx_next_send_seq_no >= ctrl.tx_next_send_buffer_seq_no
        {
            // Send FIN after completed stream
            self.send_client_fin(ctrl)
        }
    }

    fn send_client_fin(&mut self, ctrl: &mut TransmissionControlBlock) {
        tracing::trace!("Initiating shutdown with FIN #{}", ctrl.tx_next_send_seq_no);
        let pkt = ctrl.create_packet(
            TcpPacketId::Fin,
            ctrl.tx_next_send_seq_no,
            ctrl.rx_last_recv_seq_no,
        );

        self.tcp_send_packet(ctrl, ctrl.ip_packet_for(pkt));
        ctrl.tx_next_send_seq_no += 1;

        // (1) Switch to FinWait1 expecting ACK of FIN
        ctrl.tx_state = TcpSenderState::Closing;
        if ctrl.state == TcpState::Established {
            ctrl.state = TcpState::FinWait1;
        }
    }

    pub(self) fn tcp_try_write(&mut self, fd: Fd, buf: &[u8]) -> Result<usize> {
        // (0) Get the socket
        let Some(mut ctrl) = self.tcp.streams.remove(&fd) else {
            return Err(Error::new(ErrorKind::InvalidInput, "invalid fd - socket dropped"))
        };

        let span = ctrl.span.clone();
        let _g = span.entered();

        // (1) If the socket is closing, send no more data
        if ctrl.state as u8 > TcpState::Established as u8
            || ctrl.tx_state != TcpSenderState::Established
        {
            self.tcp.streams.insert(fd, ctrl);
            return Ok(0);
        }

        // (2) Write as much as possible to the send buffer
        let n = ctrl.tx_buffer.append(buf);
        ctrl.tx_next_send_buffer_seq_no += n as u32;
        if n == 0 {
            self.tcp.streams.insert(fd, ctrl);
            return Err(Error::new(
                ErrorKind::WouldBlock,
                "send buffer full - would block",
            ));
        }

        self.do_sending(&mut ctrl);
        self.tcp.streams.insert(fd, ctrl);

        Ok(n)
    }

    pub(self) fn tcp_try_read(&mut self, fd: Fd, buf: &mut [u8]) -> Result<usize> {
        // (0) Get the socket
        let Some(mut ctrl) = self.tcp.streams.remove(&fd) else {
            return Err(Error::new(ErrorKind::InvalidInput, "invalid fd - socket dropped"))
        };

        let span = ctrl.span.clone();
        let _g = span.entered();

        // (1) Check for need for window updates.
        let was_full = ctrl.rx_buffer.len() == ctrl.rx_buffer.cap();

        // (2) This read operation will only read (and consume)
        // valid bytes according to the buffers state. The state
        // will be updated
        let n = ctrl.rx_buffer.read(buf);
        if n == 0 {
            let nmd = ctrl.no_more_data_closed();
            self.tcp.streams.insert(fd, ctrl);
            if nmd {
                return Ok(n);
            } else {
                return Err(Error::new(
                    ErrorKind::WouldBlock,
                    "recv buffer empty - would block",
                ));
            }
        }

        // Window advetisment
        {
            let window = ctrl.recv_window();
            let ack_no = ctrl.rx_last_recv_seq_no;
            tracing::trace!(
                "advertising a {} byte window starting at {}",
                window,
                ack_no
            );
            self.send_ack(&mut ctrl, ack_no + 1, window);
        }

        self.tcp.streams.insert(fd, ctrl);

        Ok(n)
    }

    pub(self) fn tcp_try_peek(&mut self, fd: Fd, buf: &mut [u8]) -> Result<usize> {
        // (0) Get the socket
        let Some(mut ctrl) = self.tcp.streams.remove(&fd) else {
            return Err(Error::new(ErrorKind::InvalidInput, "invalid fd - socket dropped"))
        };

        let span = ctrl.span.clone();
        let _g = span.entered();

        // (1) This peek will only be into valid slice memory
        let n = ctrl.rx_buffer.peek(&mut buf[..]);
        if n == 0 {
            self.tcp.streams.insert(fd, ctrl);
            return Err(Error::new(
                ErrorKind::WouldBlock,
                "recv buffer empty - would block",
            ));
        }

        self.tcp.streams.insert(fd, ctrl);

        Ok(n)
    }

    fn handle_data_timeout(&mut self, ctrl: &mut TransmissionControlBlock) {
        tracing::trace!(
            "data timeout, missing ack for {}..{}",
            ctrl.tx_last_ack_no,
            ctrl.tx_next_send_seq_no
        );

        // TODO: Handle permit packets
        // FIXME: +1 was there but makes no sense, so i removed it, lets see what breaks
        ctrl.tx_next_send_seq_no = ctrl.tx_last_ack_no;
        ctrl.cancel_timer();
        ctrl.set_data_timer();

        // Reset congestion control

        // ctrl.debug_cong_window
        //     .collect(ctrl.congestion_window as f64);
        // ctrl.debug_ssthresh.collect(ctrl.ssthresh as f64);

        // // TCP THAOHE
        // ctrl.ssthresh = ctrl.congestion_window / 2;
        // ctrl.congestion_window = ctrl.mss as u32;

        // TCP RENO
        ctrl.congestion_window = (ctrl.congestion_window / 2).max(ctrl.mss as u32);
        ctrl.ssthresh = ctrl.congestion_window;

        // ctrl.debug_cong_window
        //     .collect(ctrl.congestion_window as f64);
        // ctrl.debug_ssthresh.collect(ctrl.ssthresh as f64);

        // Edge case: FIN send but data missing
        // reset fin state so that the no send data can be consideed
        if ctrl.tx_state == TcpSenderState::Closing {
            ctrl.tx_state = TcpSenderState::WaitForStream;
        }

        self.do_sending(ctrl);
    }

    fn send_ack(&mut self, ctrl: &mut TransmissionControlBlock, next_expected: u32, win: u16) {
        assert!(next_expected > 0);
        let mut ack = ctrl.create_packet(TcpPacketId::Ack, ctrl.tx_next_send_seq_no, next_expected);
        if win > 0 {
            ack.window = win;
        }

        self.tcp_send_packet(ctrl, ctrl.ip_packet_for(ack));
    }
}

impl TransmissionControlBlock {
    fn no_more_data_closed(&self) -> bool {
        matches!(
            self.state,
            TcpState::CloseWait
                | TcpState::LastAck
                | TcpState::Closed
                | TcpState::Closing
                | TcpState::TimeWait
        )
    }

    fn add_inital_rtt_sample(&mut self, r: f64) {
        self.srtt = r;
        self.rttvar = r / 2.0;
        self.rto = (self.srtt + 4.0 * self.rttvar).max(0.5);

        // self.debug_rto.collect(self.rto);
    }

    fn add_rtt_sample(&mut self, r: f64) {
        const ALPHA: f64 = 0.125;
        const BETA: f64 = 0.25;

        self.rttvar = (1.0 - BETA) * self.rttvar + BETA * (self.srtt - r).abs();
        self.srtt = (1.0 - ALPHA) * self.srtt + ALPHA * r;
        self.rto = (self.srtt + 4.0 * self.rttvar).max(0.5);

        // self.debug_rto.collect(self.rto);
    }

    fn ip_packet_for(&self, tcp: TcpPacket) -> IpPacket {
        let content = tcp.to_buffer().unwrap();
        match self.local_addr {
            SocketAddr::V4(local) => IpPacket::V4(Ipv4Packet {
                dscp: 0,
                enc: 0,
                identification: 0,
                flags: Ipv4Flags {
                    df: false,
                    mf: false,
                },
                fragment_offset: 0,
                ttl: 64,
                proto: PROTO_TCP,

                src: *local.ip(),
                dest: if let IpAddr::V4(addr) = self.peer_addr.ip() {
                    addr
                } else {
                    unreachable!()
                },

                content,
            }),
            SocketAddr::V6(local) => IpPacket::V6(Ipv6Packet {
                traffic_class: 0,
                flow_label: 0,
                hop_limit: 64,
                next_header: PROTO_TCP,

                src: *local.ip(),
                dest: if let IpAddr::V6(addr) = self.peer_addr.ip() {
                    addr
                } else {
                    unreachable!()
                },

                content,
            }),
        }
    }

    fn create_packet(&self, id: TcpPacketId, seq_no: u32, expected: u32) -> TcpPacket {
        let ack = expected != 0 || id != TcpPacketId::Syn;
        let syn = id == TcpPacketId::Syn;
        let fin = id == TcpPacketId::Fin;

        TcpPacket {
            src_port: self.local_addr.port(),
            dest_port: self.peer_addr.port(),
            seq_no,
            ack_no: expected,
            flags: TcpFlags::new().ack(ack).syn(syn).fin(fin),
            window: 0,
            urgent_ptr: 0,
            options: Vec::new(),
            content: Vec::new(),
        }
    }

    fn syn_options(&self) -> Vec<TcpOption> {
        vec![
            TcpOption::MaximumSegmentSize(self.mss),
            TcpOption::EndOfOptionsList(),
        ]
    }

    fn apply_syn_options(&mut self, options: &[TcpOption]) {
        if let Some(mss) = options.iter().find_map(|v| {
            if let TcpOption::MaximumSegmentSize(mss) = v {
                Some(mss)
            } else {
                None
            }
        }) {
            self.mss = self.mss.min(*mss);
        }
    }

    fn set_data_timer(&mut self) {
        tracing::trace!(
            "scheduling data timer for {}",
            SimTime::now() + self.timeout
        );
        self.timer += 1;
        schedule_in(
            Message::new()
                .kind(KIND_IO_TIMEOUT)
                .id(self.timer)
                .content(self.fd)
                .build(),
            Duration::from_secs_f64(self.rto),
        );
    }

    fn cancel_timer(&mut self) {
        tracing::trace!("canceling data timer");
        self.timer += 1;
    }

    fn send_buffer_len(&self) -> u32 {
        self.tx_next_send_buffer_seq_no - self.tx_next_send_seq_no
    }

    fn send_window(&self) -> u32 {
        self.tx_max_send_seq_no - (self.tx_next_send_seq_no - 1)
    }

    fn recv_window(&self) -> u16 {
        self.rx_buffer.rem() as u16
    }

    fn set_timer(&mut self, expiration: Duration) {
        self.timer += 1;
        schedule_in(
            Message::new()
                .kind(KIND_IO_TIMEOUT)
                .id(self.timer)
                .content(self.fd)
                .build(),
            expiration,
        )
    }

    fn reset_connection_pars(&mut self) {
        self.state = TcpState::Closed;

        self.local_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
        self.peer_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);

        self.tx_last_ack_no = 0;
        self.tx_next_send_seq_no = 0;
        self.tx_next_send_buffer_seq_no = 0;

        self.rx_last_recv_seq_no = 0;
        self.tx_max_send_seq_no = 0;

        self.congestion_window = self.mss as u32;
        self.congestion_avoid_counter = 0;
    }
}
