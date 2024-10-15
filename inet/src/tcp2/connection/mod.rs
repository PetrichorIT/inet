use bytepack::FromBytestream;
use des::time::SimTime;
use std::{
    cmp,
    collections::{BTreeMap, VecDeque},
    io::{self, Error, ErrorKind, Write},
    net::SocketAddrV4,
    task::Waker,
    time::Duration,
};
use tracing::instrument;
use types::{
    icmpv4::{IcmpV4DestinationUnreachableCode, IcmpV4Packet, IcmpV4Type},
    icmpv6::{IcmpV6DestinationUnreachableCode, IcmpV6Packet},
    tcp::{TcpFlags, TcpOption, TcpPacket},
};

use super::{sender::TcpSender, Quad, PROTO_TCP2};

mod cfg;
mod cong;
mod reorder;

pub use cfg::*;
use cong::CongestionControl;
pub(super) use reorder::*;

bitflags::bitflags! {
    pub struct Available: u8 {
        const READ = 0b00000001;
        const WRITE = 0b00000010;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    //Listen,
    SynSent,
    SynRcvd,
    Estab,
    FinWait1,
    FinWait2,
    CloseWait,
    LastAck,
    Closing,
    TimeWait,
    Closed,
}

impl State {
    pub fn transition_to(&mut self, new: Self) {
        tracing::trace!("{self:?} -> {new:?}");
        *self = new;
    }

    pub fn is_synchronized(&self) -> bool {
        match *self {
            State::SynSent | State::SynRcvd | State::Closed => false,
            _ => true,
        }
    }

    pub fn is_writable(&self) -> bool {
        match *self {
            State::Estab | State::CloseWait => true,
            _ => false,
        }
    }
}

#[derive(Debug)]
enum PacketKind {
    Syn,
    SynAck,
    Fin,
    Ack,
    Rst,
}
use PacketKind::*;

pub struct Connection {
    pub state: State,
    pub snd: SendSequenceSpace,
    pub rcv: RecvSequenceSpace,
    pub timers: Timers,

    pub incoming: ReorderBuffer,
    pub cong: CongestionControl,

    pub received: VecDeque<u8>,
    pub unacked: VecDeque<u8>,
    pub quad: Quad,

    pub syn_resend_counter: usize,

    pub closed: bool,
    pub closed_at: Option<u32>,

    pub rx_wakers: Vec<Waker>,
    pub tx_wakers: Vec<Waker>,

    pub cfg: Config,
    pub error: Option<io::Error>,
}

#[derive(Clone)]
pub struct Timers {
    pub send_times: BTreeMap<u32, SimTime>,
    pub srtt: f64,
}

impl Connection {
    pub fn is_rcv_closed(&self) -> bool {
        if let State::TimeWait = self.state {
            // TODO: any state after rcvd FIN, so also CLOSE-WAIT, LAST-ACK, CLOSED, CLOSING
            true
        } else {
            false
        }
    }

    pub fn next_timeout(&self) -> Option<SimTime> {
        let oldest_send_time = self.timers.send_times.values().min()?;
        Some(*oldest_send_time + Duration::from_secs_f64(self.timers.srtt * 1.5))
    }

    pub fn is_synchronized(&self) -> bool {
        self.state.is_synchronized()
    }

    pub fn wake_all(&mut self, snd: &mut TcpSender) {
        self.wake_rx(snd);
        self.wake_tx(snd);
    }

    pub fn wake_rx(&mut self, snd: &mut TcpSender) {
        // tracing::trace!("waking {} rx wakers", self.tx_wakers.len());
        snd.wake(&mut self.rx_wakers);
    }

    pub fn wake_tx(&mut self, snd: &mut TcpSender) {
        // tracing::trace!("waking {} tx wakers", self.tx_wakers.len());
        snd.wake(&mut self.tx_wakers);
    }

    pub fn is_readable(&self) -> bool {
        self.is_rcv_closed() || !self.received.is_empty()
    }

    pub fn is_writable(&self) -> bool {
        self.state.is_writable() && self.unacked.len() < self.cfg.send_buffer_cap
    }

    fn availability(&self) -> Available {
        let mut a = Available::empty();
        if self.is_rcv_closed() || !self.received.is_empty() {
            a |= Available::READ;
        }
        // TODO: take into account self.state
        // TODO: set Available::WRITE
        a
    }
}

/// State of the Send Sequence Space (RFC 793 S3.2 F4)
///
/// ```text
///            1         2          3          4
///       ----------|----------|----------|----------
///              SND.UNA    SND.NXT    SND.UNA
///                                   +SND.WND
///
/// 1 - old sequence numbers which have been acknowledged
/// 2 - sequence numbers of unacknowledged data
/// 3 - sequence numbers allowed for new data transmission
/// 4 - future sequence numbers which are not yet allowed
/// ```
pub struct SendSequenceSpace {
    /// send unacknowledged
    pub una: u32,
    /// send next
    pub nxt: u32,
    /// send window
    pub wnd: u16,
    /// send urgent pointer
    pub up: bool,
    /// segment sequence number used for last window update
    pub wl1: u32,
    /// segment acknowledgment number used for last window update
    pub wl2: u32,
    /// initial send sequence number
    pub iss: u32,
}

/// State of the Receive Sequence Space (RFC 793 S3.2 F5)
///
/// ```text
///                1          2          3
///            ----------|----------|----------
///                   RCV.NXT    RCV.NXT
///                             +RCV.WND
///
/// 1 - old sequence numbers which have been acknowledged
/// 2 - sequence numbers allowed for new reception
/// 3 - future sequence numbers which are not yet allowed
/// ```
pub struct RecvSequenceSpace {
    /// receive next
    pub nxt: u32,
    /// receive window
    pub wnd: u16,
    /// receive urgent pointer
    pub up: u32,
    /// initial receive sequence number
    pub irs: u32,
}

impl Connection {
    pub fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let nread = self.peek(buf)?;
        drop(self.received.drain(..nread));
        return Ok(nread);
    }

    pub fn peek(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // RFC 9293 - 3.10.3. RECEIVE Call

        // LISTEN, SYN-SNT, SYN-RCVD
        // Queue for processing after entering ESTABLISHED state. If there is no room to queue this request,
        // respond with "error: insufficient resources".
        if let State::SynSent | State::SynRcvd = self.state {
            // This is illegal, since no TcpStream should exist before ESTABLISHED is reached
            // -> do never allow requuest queuing
            return Err(Error::new(
                ErrorKind::Other,
                "insufficient resources - unexpected read before Estab",
            ));
        }

        if let State::Estab | State::FinWait1 | State::FinWait2 | State::CloseWait = self.state {
            // If insufficient incoming segments are queued to satisfy the request, queue the request.
            // If there is no queue space to remember the RECEIVE, respond with "error: insufficient resources".
            // -> No request queuing is allowed, since we work non-blocking poll based

            if self.is_rcv_closed() && self.received.is_empty() {
                return Ok(0);
            }

            if self.received.is_empty() {
                return Err(Error::new(
                    ErrorKind::WouldBlock,
                    "no bytes in rx buffer yet",
                ));
            }

            // Reassemble queued incoming segments into receive buffer and return to user.
            // Mark "push seen" (PUSH) if this is the case.
            // -> no need for PUSH mng, since all data is PSH

            // If RCV.UP is in advance of the data currently being passed to the user, notify the user of the presence of urgent data.
            // -> Not part of the tokio API

            let mut nread = 0;
            let (head, tail) = self.received.as_slices();
            let hread = std::cmp::min(buf.len(), head.len());
            buf[..hread].copy_from_slice(&head[..hread]);
            nread += hread;
            let tread = std::cmp::min(buf.len() - nread, tail.len());
            buf[hread..(hread + tread)].copy_from_slice(&tail[..tread]);
            nread += tread;

            // When the TCP endpoint takes responsibility for delivering data ...
            // -> We already send an ACK, read interacts only with the buffer
            return Ok(nread);
        }

        Err(Error::new(ErrorKind::InvalidInput, "connection closing"))
    }

    pub fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.unacked.len() >= self.cfg.send_buffer_cap {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "too many bytes in tx buffer",
            ));
        }

        let n = cmp::min(buf.len(), self.cfg.send_buffer_cap - self.unacked.len());
        self.unacked.extend(buf[..n].iter());
        tracing::trace!("Connection::write({}) = {n}", buf.len());
        Ok(n)
    }

    pub fn recv_window(&self) -> u16 {
        (self.cfg.recv_buffer_cap - self.received.len()) as u16
    }

    pub fn connect(nic: &mut TcpSender, quad: Quad, cfg: Config) -> io::Result<Self> {
        assert!(!quad.dst.ip().is_unspecified());

        let iss = cfg.iss_for(&quad, &[]);
        let wnd = 1024;

        // Default MSS according to RFC 9293
        // -> 3.7.1. Maximum Segment Size Option
        // If an MSS Option is not received at connection setup, TCP implementations MUST assume a
        // default send MSS of 536 (576 - 40) for IPv4 or 1220 (1280 - 60) for IPv6 (MUST-15).
        //
        // We just set our own MSS and always send it elsewise
        let mss = cfg.mss.unwrap_or(if quad.is_ipv4() { 536 } else { 1220 });

        let mut c = Connection {
            timers: Timers {
                send_times: Default::default(),
                srtt: Duration::from_secs(10).as_secs_f64(),
            },
            state: State::SynSent,
            snd: SendSequenceSpace::new(iss, wnd),
            rcv: RecvSequenceSpace::empty(
                u16::try_from(cfg.recv_buffer_cap).expect("failed to downcast"),
            ),
            quad,
            syn_resend_counter: 0,

            incoming: ReorderBuffer::default(),
            cong: CongestionControl::new(cfg.enable_congestion_control, mss),

            received: VecDeque::with_capacity(cfg.recv_buffer_cap),
            unacked: VecDeque::with_capacity(cfg.send_buffer_cap),

            rx_wakers: Vec::new(),
            tx_wakers: Vec::new(),

            closed: false,
            closed_at: None,

            cfg,
            error: None,
        };

        c.send_pkt(nic, Syn, c.snd.nxt, 0)?;
        Ok(c)
    }

    pub fn accept(
        nic: &mut TcpSender,
        quad: Quad,
        pkt: TcpPacket,
        cfg: Config,
    ) -> io::Result<Option<Self>> {
        if !pkt.flags.contains(TcpFlags::SYN) {
            // only expected SYN packet
            return Ok(None);
        }

        // Default MSS according to RFC 9293
        // -> 3.7.1. Maximum Segment Size Option
        let mss = cfg.mss.unwrap_or(if quad.is_ipv4() { 536 } else { 1220 });

        let iss = cfg.iss_for(&quad, &[]);
        let wnd = 1024;
        let mut c = Connection {
            timers: Timers {
                send_times: Default::default(),
                srtt: Duration::from_secs(10).as_secs_f64(),
            },
            state: State::SynRcvd,
            snd: SendSequenceSpace::new(iss, wnd),
            rcv: RecvSequenceSpace::from_syn(&pkt),
            quad,
            syn_resend_counter: 0,

            incoming: ReorderBuffer::default(),
            cong: CongestionControl::new(cfg.enable_congestion_control, mss),

            received: VecDeque::with_capacity(cfg.recv_buffer_cap),
            unacked: VecDeque::with_capacity(cfg.send_buffer_cap),

            rx_wakers: Vec::new(),
            tx_wakers: Vec::new(),

            closed: false,
            closed_at: None,

            cfg,
            error: None,
        };

        // need to start establishing a connection
        c.send_pkt(nic, SynAck, c.snd.nxt, 0)?;
        Ok(Some(c))
    }

    #[instrument(skip(self, nic, limit))]
    fn send_pkt(
        &mut self,
        nic: &mut TcpSender,
        kind: PacketKind,
        seq: u32,
        mut limit: usize,
    ) -> io::Result<usize> {
        let mut packet = TcpPacket {
            src_port: self.quad.src.port(),
            dst_port: self.quad.dst.port(),
            window: self.recv_window(),
            seq_no: seq,
            ack_no: self.rcv.nxt,
            flags: TcpFlags::empty()
                .putv(TcpFlags::SYN, matches!(kind, Syn | SynAck))
                .putv(TcpFlags::ACK, matches!(kind, SynAck | Ack | Fin))
                .putv(TcpFlags::FIN, matches!(kind, Fin))
                .putv(TcpFlags::RST, matches!(kind, Rst)),
            urgent_ptr: 0,
            options: self.options_for_kind(kind),
            content: Vec::new(),
        };

        // TODO: return +1 for SYN/FIN

        let mut offset = seq.wrapping_sub(self.snd.una) as usize;
        // we need to special-case the two "virtual" bytes SYN and FIN
        if let Some(closed_at) = self.closed_at {
            if seq == closed_at.wrapping_add(1) {
                // trying to write following FIN
                offset = 0;
                limit = 0;
            }
        }

        // Max TCP packet size
        limit = limit.min(self.cong.mss as usize);

        let (mut h, mut t) = self.unacked.as_slices();
        if h.len() >= offset {
            h = &h[offset..];
        } else if limit > 0 {
            let skipped = h.len();
            h = &[];
            t = &t[(offset - skipped)..];
        }

        let max_data = std::cmp::min(limit, h.len() + t.len());

        // write out the payload
        let payload_bytes = {
            let mut written = 0;
            let mut limit = max_data;

            // first, write as much as we can from h
            let p1l = std::cmp::min(limit, h.len());
            written += packet.content.write(&h[..p1l])?;
            limit -= written;

            // then, write more (if we can) from t
            let p2l = std::cmp::min(limit, t.len());
            written += packet.content.write(&t[..p2l])?;
            written
        };

        let mut next_seq = seq.wrapping_add(payload_bytes as u32);
        if packet.flags.contains(TcpFlags::SYN) {
            next_seq = next_seq.wrapping_add(1);
        }
        if packet.flags.contains(TcpFlags::FIN) {
            next_seq = next_seq.wrapping_add(1);
        }
        if wrapping_lt(self.snd.nxt, next_seq) {
            self.snd.nxt = next_seq;
        }
        self.timers.send_times.insert(seq, (self.cfg.clock)());

        tracing::info!(
            "sending seq={} ack={} data={:?} flags={:?} (len = {})",
            packet.seq_no,
            packet.ack_no,
            packet.content.iter().take(20).collect::<Vec<_>>(),
            packet.flags,
            packet.content.len(),
        );
        nic.send(packet);
        Ok(payload_bytes)
    }

    fn options_for_kind(&mut self, kind: PacketKind) -> Vec<TcpOption> {
        let mut options = match kind {
            // RFC 9293
            // ->  3.7.1. Maximum Segment Size Option
            // TCP implementations SHOULD send an MSS Option in every SYN segment when its receive MSS differs from
            // the default 536 for IPv4 or 1220 for IPv6 (SHLD-5), and MAY send it always (MAY-3).
            Syn => {
                let is_default = self.cong.mss == self.quad.default_mss();
                if !is_default {
                    vec![TcpOption::MaximumSegmentSize(self.cong.mss)]
                } else {
                    Vec::new()
                }
            }
            _ => Vec::new(),
        };

        if !options.is_empty() {
            options.push(TcpOption::EndOfOptionsList())
        }
        options
    }

    fn send_rst(&mut self, nic: &mut TcpSender, seq: u32) -> io::Result<()> {
        // TODO: fix sequence numbers here
        // If the incoming segment has an ACK field, the reset takes its
        // sequence number from the ACK field of the segment, otherwise the
        // reset has sequence number zero and the ACK field is set to the sum
        // of the sequence number and segment length of the incoming segment.
        // The connection remains in the same state.
        //
        // TODO: handle synchronized RST
        // 3.  If the connection is in a synchronized state (ESTABLISHED,
        // FIN-WAIT-1, FIN-WAIT-2, CLOSE-WAIT, CLOSING, LAST-ACK, TIME-WAIT),
        // any unacceptable segment (out of window sequence number or
        // unacceptible acknowledgment number) must elicit only an empty
        // acknowledgment segment containing the current send-sequence number
        // and an acknowledgment indicating the next sequence number expected
        // to be received, and the connection remains in the same state.

        self.send_pkt(nic, Rst, seq, 0)?;
        Ok(())
    }

    /// The number of bytes in transit, with no ack just yet
    pub fn num_unacked_bytes(&self) -> u32 {
        self.closed_at
            .unwrap_or(self.snd.nxt)
            .wrapping_sub(self.snd.una)
    }

    /// The number of bytes in the tx buffer,
    pub fn num_unsend_bytes(&self) -> Option<u32> {
        (self.unacked.len() as u32).checked_sub(self.num_unacked_bytes())
    }

    pub fn on_tick(&mut self, nic: &mut TcpSender) -> io::Result<()> {
        if let State::FinWait2 | State::TimeWait | State::Closed = self.state {
            // we have shutdown our write side and the other side acked, no need to (re)transmit anything
            return Ok(());
        }

        // tracing::info!("ON TICK: state {:?} una {} nxt {} unacked {:?}",
        //           self.state, self.send.una, self.send.nxt, self.unacked);

        let now = (self.cfg.clock)();
        let waited_for = self
            .timers
            .send_times
            .range(self.snd.una..)
            .next()
            .map(|t| now - *t.1);

        let should_retransmit = if let Some(waited_for) = waited_for {
            waited_for >= Duration::from_secs(1)
                && waited_for.as_secs_f64() >= 1.5 * self.timers.srtt
        } else {
            false
        };

        if should_retransmit {
            tracing::info!("retransmitting packet");
            let resend = std::cmp::min(self.unacked.len() as u32, self.snd.wnd as u32);
            if resend < self.snd.wnd as u32 && self.closed {
                // can we include the FIN?
                self.closed_at = Some(self.snd.una.wrapping_add(self.unacked.len() as u32));
                self.cong.on_timeout();
                self.send_pkt(nic, Fin, self.snd.una, resend as usize)?;
            } else if let State::SynSent = self.state {
                assert_eq!(resend, 0);

                if self.syn_resend_counter >= self.cfg.syn_resent_count {
                    self.closed = true;
                    self.closed_at = Some(self.snd.una);
                    self.state.transition_to(State::Closed);

                    tracing::warn!("syn resend count exceeded - closing socket");

                    self.error = Some(io::Error::new(
                        io::ErrorKind::ConnectionRefused,
                        "host unreachable: syn resend count exceeded",
                    ));
                    self.wake_rx(nic);
                    self.wake_tx(nic);

                    return Ok(());
                }

                self.syn_resend_counter += 1;
                self.send_pkt(nic, Syn, self.snd.una, 0)?;
            } else if let State::SynRcvd = self.state {
                self.send_pkt(nic, SynAck, self.snd.una, 0)?;
            } else {
                self.cong.on_timeout();
                self.send_pkt(nic, Ack, self.snd.una, resend as usize)?;
            }
        } else {
            loop {
                let Some(num_unsend_bytes) = self.num_unsend_bytes() else {
                    break;
                };

                tracing::trace!(num_unsend_bytes, "");

                // we should send new data if we have new data and space in the window
                if num_unsend_bytes == 0 && self.closed_at.is_some() {
                    return Ok(());
                }

                let remaining_window_space = self.remaining_window_space();
                tracing::trace!(
                    remaining_window_space,
                    "unacked {} wnd {}",
                    self.num_unacked_bytes(),
                    self.snd.wnd
                );
                if remaining_window_space == 0 {
                    return Ok(());
                }

                let bytes_to_be_sent = cmp::min(num_unsend_bytes, remaining_window_space);
                if bytes_to_be_sent < remaining_window_space
                    && self.closed
                    && self.closed_at.is_none()
                {
                    // If there is space left in the window and we are closed without FIN
                    // attach the virtual FIN byte
                    self.closed_at = Some(self.snd.una.wrapping_add(self.unacked.len() as u32));

                    // RFC 9293
                    // -> 3.6. Closing a Connection
                    // Case 1:
                    // Local user initiates the close In this case, a FIN segment can be constructed and placed on the outgoing segment queue.
                    // ...
                    self.send_pkt(nic, Fin, self.snd.nxt, bytes_to_be_sent as usize)?;
                } else {
                    if num_unsend_bytes == 0 {
                        break;
                    }
                    self.send_pkt(nic, Ack, self.snd.nxt, bytes_to_be_sent as usize)?;
                }
            }
        }

        Ok(())
    }

    pub fn on_icmp_v4(&mut self, snd: &mut TcpSender, icmp: IcmpV4Packet) -> io::Result<()> {
        // # Demultiplex ICMP messages
        let ip_header = icmp.contained()?;
        if ip_header.proto != PROTO_TCP2 {
            // Not directed at us, so no error
            return Ok(());
        }

        let tcp = TcpPacket::from_slice(&ip_header.content)?;
        let implied_quad = Quad {
            src: SocketAddrV4::new(ip_header.src, tcp.src_port).into(),
            dst: SocketAddrV4::new(ip_header.dst, tcp.dst_port).into(),
        };
        if implied_quad != self.quad {
            return Ok(());
        }

        if let IcmpV4Type::DestinationUnreachable { code, .. } = icmp.typ {
            use IcmpV4DestinationUnreachableCode::*;
            // Hard errors
            if let ProtocolUnreachable | PortUnreachable | DatagramToBig = code {
                tracing::warn!("ICMP: destinations unreachable, closing connection");
                // -> Rst with an valid ack
                let mut rst = TcpPacket::new(
                    self.quad.dst.port(),
                    self.quad.src.port(),
                    self.rcv.nxt,
                    self.snd.una.wrapping_add(1),
                    0,
                    Vec::new(),
                );
                rst.flags.insert(TcpFlags::RST);
                rst.flags.insert(TcpFlags::ACK);
                // TODO: Add custom error handling
                self.on_packet(snd, rst)?;
                return Ok(());
            }

            if let NetworkUnreachable | HostUnreachable | SourceRouteFailed = code {
                // Do not abort,
                // but inform application
                // -> TODO
            }
        };
        Ok(())
    }

    pub fn on_packet(&mut self, nic: &mut TcpSender, seg: TcpPacket) -> io::Result<Available> {
        if let State::SynSent = self.state {
            // RFC 9293 -  3.10.7 SEGMENT ARRIVES
            // -> Defines custom handlers for state SYN_SENT
            return self.on_packet_syn_sent(nic, seg);
        }
        // Otherwise,
        // States = SYN-RECEIVED, ESTABLISHED, FIN-WAIT-1, FIN-WAIT-2, CLOSE-WAIT, CLOSING, LAST-ACK, TIME-WAIT

        // RFC 9293 - 3.10.7.4. Other States
        // First, check sequence number:

        // Segments are processed in sequence. Initial tests on arrival are used to discard old duplicates,
        // but further processing is done in SEG.SEQ order. If a segment's contents straddle the boundary
        // between old and new, only the new parts are processed.
        //
        // Condition: RCV.NXT < SEG.SEQ < WEND

        // -> Only for packets of an established connection aka ACK do reordering
        //    else you might buffer packets of handshakes or RST
        if seg.flags.contains(TcpFlags::ACK) {
            let wend = self.rcv.nxt.wrapping_add(self.recv_window() as u32);
            tracing::info!(self.rcv.nxt, seg.seq_no, wend, "");
            if wrapping_lt(self.rcv.nxt, seg.seq_no) && wrapping_lt(seg.seq_no, wend) {
                // check the validity of the segment non-the-less to not get out of window packets
                let okay = self.packet_is_valid(&seg);
                if okay {
                    self.incoming.enqueue(seg);
                    return Ok(self.availability());
                }
                // process as usual if packet is not okay, to not duplicate not-okay logic
            }
        }

        let mut last = self.on_inorder_packet(nic, seg)?;
        while let Some(next_pkt) = self.incoming.next(self.rcv.nxt) {
            last = self.on_inorder_packet(nic, next_pkt)?;
        }
        Ok(last)
    }

    fn on_inorder_packet(
        &mut self,
        nic: &mut TcpSender<'_>,
        seg: TcpPacket,
    ) -> Result<Available, Error> {
        // first, check that sequence numbers are valid (RFC 793 S3.3)
        let seqn = seg.seq_no;
        let mut slen = seg.content.len() as u32;
        // # virtual syn and fin bytes
        // the first and last byte are not really send as payload, but rather as an indication that the stream
        // starts or ends. This means seq_no is not exactly pck_len defined but with a + 1
        if seg.flags.contains(TcpFlags::SYN) {
            slen += 1;
        };
        if seg.flags.contains(TcpFlags::FIN) {
            slen += 1;
        };

        // max allowed recv seq_no
        // -> aka. last byte that will be accepted in the input stream
        let wend = self.rcv.nxt.wrapping_add(self.rcv.wnd as u32);

        tracing::info!(
            "recv({seqn}, len: {slen} (real {}), wend: {wend})",
            seg.content.len(),
        );

        // In general, the processing of received segments MUST be implemented to aggregate ACK segments whenever possible (MUST-58).
        // For example, if the TCP endpoint is processing a series of queued segments, it MUST process them all before sending any ACK
        // segments (MUST-59).
        // -> Since we are in a discrete event simulation, multiple packets cannot be received at a time, since we are perfectly timed.

        // There are four cases for the acceptability test for an incoming segment:
        // If the RCV.WND is zero, no segments will be acceptable, but special allowance
        // should be made to accept valid ACKs, URGs, and RSTs.
        let okay = self.packet_is_valid(&seg);

        // If an incoming segment is not acceptable, an acknowledgment should be sent in reply
        // (unless the RST bit is set, if so drop the segment and return): <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>
        // After sending the acknowledgment, drop the unacceptable segment and return.
        if !okay {
            tracing::error!("segment not acceptable");
            if !seg.flags.contains(TcpFlags::RST) {
                self.send_pkt(nic, Ack, self.snd.nxt, 0)?;
            }
            return Ok(self.availability());
        }

        // Note that for the TIME-WAIT state, there is an improved algorithm described in [40]
        // for handling incoming SYN segments that utilizes timestamps rather than relying on the
        // sequence number check described here. When the improved algorithm is implemented, the logic
        // above is not applicable for incoming SYN segments with Timestamp Options, received on a
        // connection in the TIME-WAIT state.
        // -> TODO

        // In the following it is assumed that the segment is the idealized segment that begins at RCV.NXT
        // and does not exceed the window. One could tailor actual segments to fit this assumption by
        // trimming off any portions that lie outside the window (including SYN and FIN)
        // and only processing further if the segment then begins at RCV.NXT.
        // Segments with higher beginning sequence numbers SHOULD be held for later processing (SHLD-31).
        // -> TODO Reorder and Trimming Buffer

        // Second, check the RST bit:
        if seg.flags.contains(TcpFlags::RST) {
            return self.on_rst(seqn, wend, nic);
        }

        // Third, check security: ...
        // -> Will not be implemented

        // Process the MSS options
        self.on_tcp_options(&seg);

        // Fourth, check the SYN bit:
        if seg.flags.contains(TcpFlags::SYN) {
            // !Important
            // RFC 9293 omitt the fact that simultaneous ope, does not work with an event processing
            // described in 3.10.7.4, since all SYN flags will be unexpected in states from SYN_RCVD.
            // However, on simultaneous open, SYN-ACKs act as the final ACK nessecary for the handshake, so they are not unexpected
            let is_sim_open = seg.flags.contains(TcpFlags::ACK)
                && is_between_wrapped(self.snd.una.wrapping_add(1), seg.ack_no, self.snd.nxt);

            if is_sim_open {
                tracing::info!("Sim open bypass")
            } else {
                return self.on_syn(&seg, seqn, nic);
            }
        }

        // Fifth, check the ACK field:
        // if the ACK bit is off, drop the segment and return:
        if !seg.flags.contains(TcpFlags::ACK) {
            if seg.flags.contains(TcpFlags::SYN) {
                // got SYN part of initial handshake
                assert!(seg.content.is_empty());
                self.rcv.nxt = seqn.wrapping_add(1);

                if let State::SynRcvd = self.state {
                    // resend SYN ACK, it seems to be lost
                    self.send_pkt(nic, SynAck, self.snd.nxt.wrapping_sub(1), 0)?;
                }
            }
            return Ok(self.availability());
        }

        // // RFC 5961, Section 5 describes a potential blind data injection attack, and mitigation that implementations
        // // MAY choose to include (MAY-12). TCP stacks that implement RFC 5961 MUST add an input check that the ACK value
        // // is acceptable only if it is in the range of ((SND.UNA - MAX.SND.WND) =< SEG.ACK =< SND.NXT).
        // let ack_acceptable = is_between_wrapped(
        //     self.snd.una.wrapping_sub(self.snd.wnd as u32),
        //     pkt.ack_no,
        //     self.snd.nxt,
        // );

        // // All incoming segments whose ACK value doesn't satisfy the above condition MUST be discarded and an ACK sent back.
        // // The new state variable MAX.SND.WND is defined as the largest window that the local sender has ever received
        // // from its peer (subject to window scaling) or may be hard-coded to a maximum permissible window value. When
        // // the ACK value is acceptable, the per-state processing below applies:
        // // -> TODO max WINDOW
        // if !ack_acceptable {
        //     self.send_pkt(nic, Ack, self.snd.nxt, 0)?;
        //     return Ok(self.availability());
        // }

        // SYN-RECEIVED STATE
        if let State::SynRcvd = self.state {
            // If SND.UNA < SEG.ACK =< SND.NXT, then enter ESTABLISHED state and continue
            // processing with the variables below set to:
            // SND.WND <- SEG.WND
            // SND.WL1 <- SEG.SEQ
            // SND.WL2 <- SEG.ACK
            if is_between_wrapped(
                self.snd.una.wrapping_sub(1),
                seg.ack_no,
                self.snd.nxt.wrapping_add(1),
            ) {
                // must have ACKed our SYN, since we detected at least one acked byte,
                // and we have only sent one byte (the SYN).
                tracing::info!("established connection from ACK");
                self.state.transition_to(State::Estab);

                self.snd.wnd = seg.window;
                self.snd.wl1 = seg.seq_no;
                self.snd.wl2 = seg.ack_no;

                self.wake_rx(nic);
                self.wake_tx(nic);
            } else {
                // If the segment acknowledgment is not acceptable, form a reset segment
                // <SEQ=SEG.ACK><CTL=RST> and send it.
                self.send_rst(nic, seg.ack_no)?;

                // TODO: and stop processing ??, not specified
                return Ok(self.availability());
            }
        }

        // acked some code, expecting all ack from now
        let ackn = seg.ack_no;

        // ESTABLISHED STATE
        //   ...
        // CLOSE-WAIT STATE
        //   Do the same processing as for the ESTABLISHED state.
        // Also used in FIN-WAIT-1, FIN-WAIT-2, CLOSING,
        if let State::Estab | State::FinWait1 | State::FinWait2 | State::LastAck | State::Closing =
            self.state
        {
            // If SND.UNA < SEG.ACK =< SND.NXT, then set SND.UNA <- SEG.ACK.
            // Any segments on the retransmission queue that are thereby entirely acknowledged are removed.
            // Users should receive positive acknowledgments for buffers that have been SENT and fully acknowledged
            // (i.e., SEND buffer should be returned with "ok" response).
            // If the ACK is a duplicate (SEG.ACK =< SND.UNA), it can be ignored.
            // If the ACK acks something not yet sent (SEG.ACK > SND.NXT), then send an ACK, drop the segment, and return.

            // If SND.UNA =< SEG.ACK =< SND.NXT, the send window should be updated.
            // If (SND.WL1 < SEG.SEQ or (SND.WL1 = SEG.SEQ and SND.WL2 =< SEG.ACK)),
            // set SND.WND <- SEG.WND, set SND.WL1 <- SEG.SEQ, and set SND.WL2 <- SEG.ACK.
            if is_between_wrapped(self.snd.una, ackn, self.snd.nxt.wrapping_add(1)) {
                if self.snd.wl1 < seg.seq_no
                    || (self.snd.wl1 == seg.seq_no && self.snd.wl2 <= seg.ack_no)
                {
                    self.snd.wnd = seg.window;
                    self.snd.wl1 = seg.seq_no;
                    self.snd.wl2 = seg.ack_no;
                }
            }

            if is_between_wrapped(self.snd.una, ackn, self.snd.nxt.wrapping_add(1)) {
                tracing::info!(
                    "ack for {} (last: {}, wnd: {}); prune {} bytes",
                    ackn,
                    self.snd.una,
                    self.snd.wnd,
                    ackn - self.snd.una
                );

                // If unacked is not empty, ack did something actually,
                if !self.unacked.is_empty() {
                    // seq no of lasted unacked byte, corrected for virtual bytes
                    let data_start = if self.snd.una == self.snd.iss {
                        // send.una hasn't been updated yet with ACK for our SYN, so data starts just beyond it
                        self.snd.una.wrapping_add(1)
                    } else {
                        self.snd.una
                    };

                    // number of acked bytes, to be drained from the buffer
                    let acked_data_end =
                        std::cmp::min(ackn.wrapping_sub(data_start) as usize, self.unacked.len());
                    self.unacked.drain(..acked_data_end);

                    // We go an ack, reset send timers, we can send once more
                    let old = std::mem::replace(&mut self.timers.send_times, BTreeMap::new());

                    let una = self.snd.una;
                    let srtt = &mut self.timers.srtt;

                    let now = (self.cfg.clock)();

                    // add new send timer, where old timers are evaluated
                    // -> if timer was for now acked bytes -> calculate rrt with it
                    // -> if timer is for yet unacked bytes -> keep it
                    self.timers
                        .send_times
                        .extend(old.into_iter().filter_map(|(seq, sent)| {
                            if is_between_wrapped(una, seq, ackn) {
                                let elapsed = (now - sent).as_secs_f64();
                                *srtt = 0.8 * *srtt + (1.0 - 0.8) * elapsed;
                                None
                            } else {
                                Some((seq, sent))
                            }
                        }));

                    let n = ackn - self.snd.una;
                    self.cong.on_ack(n, self.snd.wnd as u32);

                    // Now is place to write more data
                    self.wake_tx(nic);
                }

                // set last ack no
                self.snd.una = ackn;
            }

            // TODO: if unacked empty and waiting flush, notify
        }

        // FIN-WAIT-2 STATE
        // In addition to the processing for the ESTABLISHED state, if the retransmission queue is empty,
        // the user's CLOSE can be acknowledged ("ok") but do not delete the TCB.
        if let State::FinWait2 = self.state {
            if self.num_unacked_bytes() == 0 {
                // TODO: Acknowledge close()
            }
        }

        // TIME-WAIT STATE
        // The only thing that can arrive in this state is a retransmission of the remote FIN.
        // Acknowledge it, and restart the 2 MSL timeout.
        if let State::TimeWait = self.state {
            // Should always be true
            if seg.flags.contains(TcpFlags::FIN) {
                self.send_pkt(nic, Ack, self.snd.nxt, 0)?;
                // TODO: MLS*2
            }
        }

        // FIN-WAIT-1 STATE
        //   In addition to the processing for the ESTABLISHED state, if the FIN segment is now acknowledged,
        //   then enter FIN-WAIT-2 and continue processing in that state.
        // CLOSING STATE
        //   In addition to the processing for the ESTABLISHED state, if the ACK acknowledges our FIN,
        //   then enter the TIME-WAIT state; otherwise, ignore the segment.
        // LAST-ACK STATE
        //   The only thing that can arrive in this state is an acknowledgment of our FIN.
        //   If our FIN is now acknowledged, delete the TCB, enter the CLOSED state, and return.
        if let State::FinWait1 | State::Closing | State::LastAck = self.state {
            // This should always be true
            if let Some(closed_at) = self.closed_at {
                // we got an ack, check if it is for the FIN
                // since una == FIN seq no (una is final since next will not move, since we are write-closed)
                if self.snd.una == closed_at.wrapping_add(1) {
                    // our FIN has been ACKed!
                    let new_state = match self.state {
                        State::FinWait1 => State::FinWait2,
                        State::Closing => State::TimeWait,
                        State::LastAck => State::Closed,
                        _ => unreachable!(),
                    };
                    tracing::info!("received ACK for FIN ({:?} -> {:?})", self.state, new_state);
                    self.state.transition_to(new_state);
                }
            }
        }

        // Sixth, check the URG bit:
        if seg.flags.contains(TcpFlags::URG) {
            match self.state {
                State::Estab | State::FinWait1 | State::FinWait2 => {
                    // If the URG bit is set, RCV.UP <- max(RCV.UP,SEG.UP), and signal the user that the remote side has
                    // urgent data if the urgent pointer (RCV.UP) is in advance of the data consumed.
                    // If the user has already been signaled (or is still in the "urgent mode")
                    // for this continuous sequence of urgent data, do not signal the user again.
                    self.rcv.up = self
                        .rcv
                        .up
                        .max(seg.seq_no.wrapping_add(seg.urgent_ptr as u32));
                }
                _ => {
                    // This should not occur since a FIN has been received from the remote side. Ignore the URG.
                }
            }
        }

        // Seventh, process the segment text:
        if !seg.content.is_empty() {
            // ESTABLISHED STATE, FIN-WAIT-1 STATE, FIN-WAIT-2 STATE
            if let State::Estab | State::FinWait1 | State::FinWait2 = self.state {
                // Once in the ESTABLISHED state, it is possible to deliver segment data to user RECEIVE buffers.
                // Data from segments can be moved into buffers until either the buffer is full or the segment is empty.
                // If the segment empties and carries a PUSH flag, then the user is informed, when the buffer is returned,
                // that a PUSH has been received.
                // -> We always wake, so we treat all segments as PSH

                // When the TCP endpoint takes responsibility for delivering the data to the user,
                // it must also acknowledge the receipt of the data.
                // -> We send an ACK at the end of this block

                // offset of received data to expected data
                // we might get a packet further to the furutre
                // -> never negative, since seq_no was checked
                let mut unread_data_at = self.rcv.nxt.wrapping_sub(seqn) as usize;

                // FIN escape hatch
                if unread_data_at > seg.content.len() {
                    // we must have received a re-transmitted FIN that we have already seen
                    // nxt points to beyond the fin, but the fin is not in data!
                    assert_eq!(unread_data_at, seg.content.len() + 1);
                    unread_data_at = 0;
                }

                // Extend the incoming data
                self.received.extend(&seg.content[unread_data_at..]);

                // Once the TCP takes responsibility for the data it advances
                // RCV.NXT over the data accepted, and adjusts RCV.WND as
                // apporopriate to the current buffer availability. The total of
                // RCV.NXT and RCV.WND should not be reduced.
                // -> the actual recv wnd is computed on the fly, wnd is only the cap
                self.rcv.nxt = seqn.wrapping_add(seg.content.len() as u32);

                // Since pkt.content is non empty, new data was received, rx ready
                self.wake_rx(nic);

                // A TCP implementation MAY send an ACK segment acknowledging RCV.NXT when a valid segment
                // arrives that is in the window but not at the left window edge (MAY-13).
                // -> We always ACK for now, but we should try to pack acks in the future

                // Send an acknowledgment of the form: <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>
                // This acknowledgment should be piggybacked on a segment being transmitted if possible without incurring undue delay.
                // TODO: maybe just tick to piggyback ack on data?
                self.send_pkt(nic, Ack, self.snd.nxt, 0)?;
            }
            // For other states
            // This should not occur since a FIN has been received from the remote side. Ignore the segment text.
        }

        // Eighth, check the FIN bit:
        if seg.flags.contains(TcpFlags::FIN) {
            // Do not process the FIN if the state is CLOSED, LISTEN, or SYN-SENT since the SEG.SEQ cannot be validated;
            // drop the segment and return.
            if let State::Closed | State::SynSent = self.state {
                return Ok(self.availability());
            }

            // If the FIN bit is set, signal the user "connection closing"
            // and return any pending RECEIVEs with same message,
            // advance RCV.NXT over the FIN, and send an acknowledgment for the FIN.
            // Note that FIN implies PUSH for any segment text not yet delivered to the user.
            // -> TODO: done in read()
            // -> PSH is already always active, so nothing to do there
            self.rcv.nxt = seg.seq_no.wrapping_add(slen);
            self.send_pkt(nic, Ack, self.snd.nxt, 0)?;
            match self.state {
                State::SynRcvd => {
                    // Do nothing
                }
                State::Estab => {
                    // Enter the CLOSE-WAIT state.
                    tracing::info!("closing recv-simplex due to received FIN (CLOSE_WAIT)");
                    self.state.transition_to(State::CloseWait);
                    self.wake_rx(nic); // Wake up to read the read(_) = 0, EOF
                }
                State::FinWait1 => {
                    // If our FIN has been ACKed (perhaps in this segment),
                    // then enter TIME-WAIT, start the time-wait timer, turn off the other timers;
                    // otherwise, enter the CLOSING state.
                    // -> TODO check ACK of own FIN, is that allready done in ACK handleing???
                    tracing::info!("closing recv-duplex due to received FIN (CLOSING)");
                    self.state.transition_to(State::Closing);
                }
                State::FinWait2 => {
                    // Enter the TIME-WAIT state. Start the time-wait timer, turn off the other timers.
                    // -> TODO: Set time wait timer
                    tracing::info!("closing recv-simplex due to received FIN (TIME_WAIT)");
                    self.state.transition_to(State::TimeWait);
                    self.wake_rx(nic); // Wake up to read the read(_) = 0, EOF
                }
                State::CloseWait | State::Closing | State::LastAck => {
                    // Remain in the X state.
                }
                State::TimeWait => {
                    // Remain in the TIME-WAIT state. Restart the 2 MSL time-wait timeout.
                    // -> TODO: Restart Time Wait Timer
                }
                // captured by upper if condition
                _ => unreachable!(),
            }
        }

        Ok(self.availability())
    }

    fn on_syn(
        &mut self,
        pkt: &TcpPacket,
        seqn: u32,
        nic: &mut TcpSender<'_>,
    ) -> Result<Available, Error> {
        if let State::SynRcvd = self.state {
            // TODO: own addition
            if !pkt.flags.contains(TcpFlags::ACK) {
                // Another SYN, SYNACK must be lost, and client must have timed out
                assert!(pkt.content.is_empty());
                self.rcv.nxt = seqn.wrapping_add(1);
                self.send_pkt(nic, SynAck, self.snd.nxt.wrapping_sub(1), 0)?;
                return Ok(Available::empty());
            }

            self.state = State::Closed;
            self.closed = true;
            self.wake_all(nic);
            Ok(Available::empty())
        } else {
            // If the SYN bit is set in these synchronized states, it may be either a legitimate new connection attempt
            // (e.g., in the case of TIME-WAIT), an error where the connection should be reset, or the result of an
            // attack attempt, as described in RFC 5961.

            // For the TIME-WAIT state, new connections can be accepted if the Timestamp Option is used and meets expectations.
            if let State::TimeWait = self.state {
                // TODO: check timestamp and re-initialized connection
            }

            // For all other cases, RFC 5961 provides a mitigation with applicability to some situations,
            // though there are also alternatives that offer cryptographic protection (see Section 7).
            // RFC 5961 recommends that in these synchronized states, if the SYN bit is set, irrespective of the sequence number,
            // TCP endpoints MUST send a "challenge ACK" to the remote peer:
            // <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>
            self.send_pkt(nic, Ack, self.snd.nxt, 0)?;

            // After sending the acknowledgment, TCP implementations MUST drop the unacceptable segment and
            // stop processing further. ...
            Ok(self.availability())
        }
    }

    fn on_tcp_options(&mut self, pkt: &TcpPacket) {
        pkt.options.iter().for_each(|opt| match opt {
            TcpOption::MaximumSegmentSize(mss) => {
                // Default MSS according to RFC 9293
                // -> 3.7.1. Maximum Segment Size Option
                //
                // We update the local MSS. We also automatically send an update
                // TODO: correct MSS computation
                if self.cong.mss != *mss {
                    tracing::info!(
                        "update maximum-segement-size {} -> {}",
                        self.cong.mss,
                        self.cong.mss.min(*mss)
                    );
                    self.cong.mss = self.cong.mss.min(*mss);
                }
            }
            _ => {}
        });
    }

    fn on_rst(
        &mut self,
        seqn: u32,
        wend: u32,
        nic: &mut TcpSender<'_>,
    ) -> Result<Available, Error> {
        if !is_between_wrapped(self.rcv.nxt, seqn, wend) {
            return Ok(Available::empty());
        }

        if self.rcv.nxt != seqn {
            // If the RST bit is set and the sequence number does not exactly match the next expected sequence value,
            // yet is within the current receive window, TCP endpoints MUST send an acknowledgment (challenge ACK):
            // <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>
            self.send_pkt(nic, Ack, self.snd.nxt, 0)?;

            // After sending the challenge ACK, TCP endpoints MUST drop the unacceptable segment and
            // stop processing the incoming packet further. ...
            return Ok(Available::empty());
        }
        match self.state {
            State::SynRcvd => {
                // If this connection was initiated with a passive OPEN (i.e., came from the LISTEN state),
                // then return this connection to LISTEN state and return. The user need not be informed.
                // -> Listen is no valid state for the Connection, set to Closed, listening socket remains
                self.state = State::Closed;
                self.closed = true;
                self.wake_all(nic);

                // If this connection was initiated with an active OPEN (i.e., came from SYN-SENT state),
                // then the connection was refused; signal the user "connection refused".
                // And in the active OPEN case, enter the CLOSED state and delete the TCB, and return.
                // -> Already done
                self.error = Some(Error::new(
                    ErrorKind::ConnectionRefused,
                    "connection refused - RST in SYN_RCVD",
                ));

                //  In either case, the retransmission queue should be flushed.
                self.unacked.clear();
                // TODO: indicate, that queued packets may be deleted
                Ok(Available::empty())
            }
            State::Estab | State::FinWait1 | State::FinWait2 | State::CloseWait => {
                // ... then any outstanding RECEIVEs and SEND should receive "reset" responses.
                // All segment queues should be flushed. Users should also receive an unsolicited
                // general "connection reset" signal. Enter the CLOSED state, delete the TCB, and return.

                self.state = State::Closed;
                self.closed = true;
                self.error = Some(Error::new(
                    ErrorKind::ConnectionReset,
                    "connection reset - RST in ESTAB'like",
                ));
                self.wake_all(nic);
                Ok(Available::empty())
            }

            State::Closing | State::LastAck | State::TimeWait => {
                // If the RST bit is set, then enter the CLOSED state, delete the TCB, and return.
                self.state = State::Closed;
                self.closed = true;
                self.wake_all(nic);
                Ok(Available::empty())
            }
            State::SynSent | State::Closed => unreachable!(),
        }
    }

    fn on_packet_syn_sent(&mut self, snd: &mut TcpSender, seg: TcpPacket) -> io::Result<Available> {
        // RFC 9293 - 3.10.7.3. SYN-SENT STATE
        // First, check the ACK bit:
        //   If the ACK bit is set:
        if seg.flags.contains(TcpFlags::ACK) {
            // If SEG.ACK =< ISS or SEG.ACK > SND.NXT, send a reset (unless the RST bit is set, if so drop the segment and return)
            // <SEQ=SEG.ACK><CTL=RST> and discard the segment. Return.
            if seg.ack_no <= self.snd.iss || seg.ack_no > self.snd.nxt {
                if !seg.flags.contains(TcpFlags::RST) {
                    self.send_rst(snd, seg.ack_no)?;
                }
                tracing::warn!(
                    seg.ack_no,
                    self.snd.iss,
                    self.snd.nxt,
                    "invalid ACK in segment"
                );
                return Ok(Available::empty());
            };

            // If SND.UNA < SEG.ACK =< SND.NXT, then the ACK is acceptable.
            // -> If not, drop the packet without rest
            if !is_between_wrapped(
                self.snd.una.wrapping_sub(1),
                seg.ack_no,
                self.snd.nxt.wrapping_add(1),
            ) {
                return Ok(Available::empty());
            }
        }

        // Second, check the RST bit:
        //   If the RST bit is set:
        if seg.flags.contains(TcpFlags::RST) {
            // A potential blind reset attack is described in RFC 5961 [9].
            // The mitigation described in that document has specific applicability explained therein, and is
            // not a substitute for cryptographic protection (e.g., IPsec or TCP-AO). A TCP implementation that
            // supports the mitigation described in RFC 5961 SHOULD first check that the sequence number exactly
            // matches RCV.NXT prior to executing the action in the next paragraph.
            tracing::info!(seg.seq_no, self.rcv.nxt, "RST");
            if seg.seq_no != self.rcv.nxt {
                return Ok(Available::empty());
            }

            // If the ACK was acceptable, then signal to the user "error: connection reset",
            // drop the segment, enter CLOSED state, delete TCB, and return.
            // Otherwise (no ACK), drop the segment and return.
            if seg.flags.contains(TcpFlags::ACK) {
                self.error = Some(Error::new(
                    ErrorKind::ConnectionReset,
                    "connection reset: RST+ACK in SYN_SNT",
                ));
                self.wake_rx(snd);
                self.wake_tx(snd);
                self.state.transition_to(State::Closed);
                return Ok(Available::empty());
            } else {
                return Ok(Available::empty());
            }
        }

        // Third, check the security:
        // -> NOP, security will not be implemented

        self.on_tcp_options(&seg);

        // Fourth, check the SYN bit:
        // This step should be reached only if the ACK is ok, or there is no ACK, and the segment did not contain a RST.
        // -> Code paths only allow valid acks, no acks AND no rst
        if seg.flags.contains(TcpFlags::SYN) {
            // If the SYN bit is on and ... then RCV.NXT is set to SEG.SEQ+1, IRS is set to SEG.SEQ. SND.UNA should
            // be advanced to equal SEG.ACK (if there is an ACK), and any segments on the retransmission queue that
            // are thereby acknowledged should be removed.
            // -> no segments are in the tx queue, no need to update
            self.rcv.nxt = seg.seq_no.wrapping_add(1);
            self.rcv.irs = seg.seq_no;
            if seg.flags.contains(TcpFlags::ACK) {
                self.snd.una = seg.ack_no;
            }

            // If SND.UNA > ISS (our SYN has been ACKed), change the connection state to ESTABLISHED,
            // form an ACK segment <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>
            if self.snd.una > self.snd.iss {
                self.state.transition_to(State::Estab);
                self.wake_rx(snd);
                self.wake_tx(snd);
                self.send_pkt(snd, Ack, self.snd.nxt, 0)?;

                // TODO: this is wrong here
                self.snd.wnd = seg.window;

                // and send it. Data or controls that were queued for transmission MAY be included. ... If there are other controls
                // or text in the segment, then continue processing at the sixth step under Section 3.10.7.4
                // where the URG bit is checked; otherwise, return.
                // -> TODO
                return Ok(Available::all());
            } else {
                // Otherwise, enter SYN-RECEIVED, form a SYN,ACK segment <SEQ=ISS><ACK=RCV.NXT><CTL=SYN,ACK>
                self.state.transition_to(State::SynRcvd);
                self.send_pkt(snd, SynAck, self.snd.iss, 0)?;

                // and send it. Set the variables:
                self.snd.wnd = seg.window;
                self.snd.wl1 = seg.seq_no;
                self.snd.wl2 = seg.ack_no;

                // If there are other controls or text in the segment, queue them for processing after the
                // ESTABLISHED state has been reached, return.

                return Ok(Available::empty());
            }
        }

        // Fifth, if neither of the SYN or RST bits is set, then drop the segment and return.
        // -> reaching this point means that these conditions are met
        Ok(Available::all())
    }

    fn packet_is_valid(&self, seg: &TcpPacket) -> bool {
        // RFC 9293 - 3.10.7.4.  Other States
        // There are four cases for the acceptability test for an incoming segment:
        // +=========+=========+======================================+
        // | Segment | Receive | Test                                 |
        // | Length  | Window  |                                      |
        // +=========+=========+======================================+
        // | 0       | 0       | SEG.SEQ = RCV.NXT                    |
        // +---------+---------+--------------------------------------+
        // | 0       | >0      | RCV.NXT =< SEG.SEQ <                 |
        // |         |         | RCV.NXT+RCV.WND                      |
        // +---------+---------+--------------------------------------+
        // | >0      | 0       | not acceptable                       |
        // +---------+---------+--------------------------------------+
        // | >0      | >0      | RCV.NXT =< SEG.SEQ <                 |
        // |         |         | RCV.NXT+RCV.WND                      |
        // |         |         |                                      |
        // |         |         | or                                   |
        // |         |         |                                      |
        // |         |         | RCV.NXT =< SEG.SEQ+SEG.LEN-1         |
        // |         |         | < RCV.NXT+RCV.WND                    |
        // +---------+---------+--------------------------------------+
        let wend = self.rcv.nxt.wrapping_add(self.recv_window() as u32);

        let mut seg_len = seg.content.len() as u32;
        if seg.flags.contains(TcpFlags::SYN) {
            seg_len += 1;
        };
        if seg.flags.contains(TcpFlags::FIN) {
            seg_len += 1;
        };

        let okay = if seg_len == 0 {
            // zero-length segment has separate rules for acceptance
            if self.recv_window() == 0 {
                if seg.seq_no != self.rcv.nxt {
                    tracing::warn!("not okay: zero-length no window not virtual byte");
                    false
                } else {
                    // allowed if seq_no is not next -> to receive virtual bytes independen of window
                    true
                }
            } else if !is_between_wrapped(self.rcv.nxt.wrapping_sub(1), seg.seq_no, wend) {
                tracing::warn!("not okay: zero-length not in rnage");
                false
            } else {
                // Else expect valid packet with virtual byte within next+1 ... wend
                true
            }
        } else {
            // When the window is empty, its always invalid to receive another packet
            if self.state == State::SynRcvd
                && seg.flags.contains(TcpFlags::SYN)
                && !seg.flags.contains(TcpFlags::ACK)
            {
                true
            } else if self.recv_window() == 0 {
                tracing::warn!("not okay: non-zero-length empty window");
                false
            } else if !is_between_wrapped(self.rcv.nxt.wrapping_sub(1), seg.seq_no, wend)
                && !is_between_wrapped(
                    self.rcv.nxt.wrapping_sub(1),
                    seg.seq_no.wrapping_add(seg_len - 1),
                    wend,
                )
            {
                // Only allowed positions of the received seq_no and seq_no+slen are
                // next+1 ... wend
                // -> aka packet must fully be within receiving windo
                tracing::warn!("not okay: non-zero-length not in rnage");
                false
            } else {
                true
            }
        };
        okay
    }

    pub fn close(&mut self) -> io::Result<()> {
        self.closed = true;
        match self.state {
            // RFC 9293
            // ->  3.6. Closing a Connection
            // Case 1:
            // Local user initiates the close In this case, a FIN segment can be constructed and placed on the outgoing segment queue.
            // No further SENDs from the user will be accepted by the TCP implementation, and it enters the FIN-WAIT-1 state.
            // RECEIVEs are allowed in this state. All segments preceding and including FIN will be retransmitted until acknowledged.
            // When the other TCP peer has both acknowledged the FIN and sent a FIN of its own, the first TCP peer can ACK this FIN.
            // Note that a TCP endpoint receiving a FIN will ACK but not send its own FIN until its user has CLOSED the connection also.
            State::SynRcvd | State::Estab => {
                self.state.transition_to(State::FinWait1);
            }
            State::FinWait1 | State::FinWait2 => {}
            State::CloseWait => self.state.transition_to(State::LastAck),
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "already closing",
                ))
            }
        };
        Ok(())
    }
}

impl SendSequenceSpace {
    pub fn new(iss: u32, wnd: u16) -> Self {
        Self {
            iss,
            una: iss,
            nxt: iss,
            wnd: wnd,
            up: false,

            wl1: 0,
            wl2: 0,
        }
    }
}

impl RecvSequenceSpace {
    pub fn from_syn(pkt: &TcpPacket) -> Self {
        Self {
            irs: pkt.seq_no,
            nxt: pkt.seq_no.wrapping_add(1),
            wnd: pkt.window,
            up: pkt.seq_no,
        }
    }

    pub const fn empty(wnd: u16) -> Self {
        Self {
            nxt: 0,
            wnd,
            irs: 0,
            up: 0,
        }
    }
}

fn wrapping_lt(lhs: u32, rhs: u32) -> bool {
    // From RFC1323:
    //     TCP determines if a data segment is "old" or "new" by testing
    //     whether its sequence number is within 2**31 bytes of the left edge
    //     of the window, and if it is not, discarding the data as "old".  To
    //     insure that new data is never mistakenly considered old and vice-
    //     versa, the left edge of the sender's window has to be at most
    //     2**31 away from the right edge of the receiver's window.
    lhs.wrapping_sub(rhs) > (1 << 31)
}

/// `start` <= `x` < end
fn is_between_wrapped(start: u32, x: u32, end: u32) -> bool {
    wrapping_lt(start, x) && wrapping_lt(x, end) || start == x
}
