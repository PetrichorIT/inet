use cong::CongestionControl;
use des::time::SimTime;
use inet_types::tcp::{TcpFlags, TcpOption, TcpPacket};
use std::{
    cmp,
    collections::{BTreeMap, VecDeque},
    io::{self, Write},
    time::Duration,
};
use tracing::instrument;

use super::{Quad, TcpHandle};

mod cong;

mod cfg;
pub use cfg::*;

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
    pub fn is_synchronized(&self) -> bool {
        match *self {
            State::SynSent | State::SynRcvd | State::Closed => false,
            _ => true,
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
    pub send: SendSequenceSpace,
    pub recv: RecvSequenceSpace,
    pub timers: Timers,

    pub cong: CongestionControl,

    pub incoming: VecDeque<u8>,
    pub unacked: VecDeque<u8>,
    pub quad: Quad,

    pub syn_resend_counter: usize,

    pub closed: bool,
    pub closed_at: Option<u32>,
    pub closed_with: Option<io::Error>,

    pub cfg: Config,
}

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

    fn availability(&self) -> Available {
        let mut a = Available::empty();
        if self.is_rcv_closed() || !self.incoming.is_empty() {
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
    pub wl1: usize,
    /// segment acknowledgment number used for last window update
    pub wl2: usize,
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
    pub up: bool,
    /// initial receive sequence number
    pub irs: u32,
}

impl Connection {
    pub fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.unacked.len() >= self.cfg.send_buffer_cap {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "too many bytes in tx buffer",
            ));
        }

        let n = cmp::min(buf.len(), self.cfg.send_buffer_cap - self.unacked.len());
        self.unacked.extend(buf[..n].iter());
        Ok(n)
    }

    pub fn recv_window(&self) -> u16 {
        (self.cfg.recv_buffer_cap - self.incoming.len()) as u16
    }

    pub fn connect(nic: &mut TcpHandle, cfg: Config) -> io::Result<Self> {
        assert!(!nic.quad.dst.ip().is_unspecified());

        let iss = cfg.iss_for(&nic.quad, &[]);
        let wnd = 1024;

        // Default MSS according to RFC 9293
        // -> 3.7.1. Maximum Segment Size Option
        // If an MSS Option is not received at connection setup, TCP implementations MUST assume a
        // default send MSS of 536 (576 - 40) for IPv4 or 1220 (1280 - 60) for IPv6 (MUST-15).
        //
        // We just set our own MSS and always send it elsewise
        let mss = cfg
            .mss
            .unwrap_or(if nic.quad.is_ipv4() { 536 } else { 1220 });

        let mut c = Connection {
            timers: Timers {
                send_times: Default::default(),
                srtt: Duration::from_secs(10).as_secs_f64(),
            },
            state: State::SynSent,
            send: SendSequenceSpace::new(iss, wnd),
            recv: RecvSequenceSpace::empty(),
            quad: nic.quad.clone(),
            syn_resend_counter: 0,

            cong: CongestionControl::disabled(mss),

            incoming: VecDeque::with_capacity(cfg.recv_buffer_cap),
            unacked: VecDeque::with_capacity(cfg.send_buffer_cap),

            closed: false,
            closed_at: None,
            closed_with: None,

            cfg,
        };

        c.send_pkt(nic, Syn, c.send.nxt, 0)?;
        Ok(c)
    }

    pub fn accept(nic: &mut TcpHandle, pkt: TcpPacket, cfg: Config) -> io::Result<Option<Self>> {
        if !pkt.flags.syn {
            // only expected SYN packet
            return Ok(None);
        }

        // Default MSS according to RFC 9293
        // -> 3.7.1. Maximum Segment Size Option
        let mss = cfg
            .mss
            .unwrap_or(if nic.quad.is_ipv4() { 536 } else { 1220 });

        let iss = cfg.iss_for(&nic.quad, &[]);
        let wnd = 1024;
        let mut c = Connection {
            timers: Timers {
                send_times: Default::default(),
                srtt: Duration::from_secs(10).as_secs_f64(),
            },
            state: State::SynRcvd,
            send: SendSequenceSpace::new(iss, wnd),
            recv: RecvSequenceSpace::from_syn(&pkt),
            quad: nic.quad.clone(),
            syn_resend_counter: 0,

            cong: CongestionControl::new(cfg.enable_congestion_control, mss),

            incoming: VecDeque::with_capacity(cfg.recv_buffer_cap),
            unacked: VecDeque::with_capacity(cfg.send_buffer_cap),

            closed: false,
            closed_at: None,
            closed_with: None,

            cfg,
        };

        // need to start establishing a connection
        c.send_pkt(nic, SynAck, c.send.nxt, 0)?;
        Ok(Some(c))
    }

    #[instrument(skip(self, nic))]
    fn send_pkt(
        &mut self,
        nic: &mut TcpHandle,
        kind: PacketKind,
        seq: u32,
        mut limit: usize,
    ) -> io::Result<usize> {
        let mut packet = TcpPacket {
            src_port: self.quad.src.port(),
            dst_port: self.quad.dst.port(),
            window: self.recv_window(),
            seq_no: seq,
            ack_no: self.recv.nxt,
            flags: TcpFlags::new()
                .syn(matches!(kind, Syn | SynAck))
                .ack(matches!(kind, SynAck | Ack | Fin))
                .fin(matches!(kind, Fin)),
            urgent_ptr: 0,
            options: self.options_for_kind(kind),
            content: Vec::new(),
        };

        // TODO: return +1 for SYN/FIN
        tracing::info!(
            "write(ack: {}, seq: {}, limit: {}) syn {:?} fin {:?}",
            self.recv.nxt - self.recv.irs,
            seq,
            limit,
            packet.flags.syn,
            packet.flags.fin,
        );

        let mut offset = seq.wrapping_sub(self.send.una) as usize;
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
        if packet.flags.syn {
            next_seq = next_seq.wrapping_add(1);
        }
        if packet.flags.fin {
            next_seq = next_seq.wrapping_add(1);
        }
        if wrapping_lt(self.send.nxt, next_seq) {
            self.send.nxt = next_seq;
        }
        self.timers.send_times.insert(seq, (self.cfg.clock)());

        tracing::info!(
            "sending seq={} ack={} data={:?} (len = {})",
            packet.seq_no,
            packet.ack_no,
            packet.content.iter().take(20).collect::<Vec<_>>(),
            packet.content.len(),
        );
        nic.tx_buffer.push(packet);
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

    fn _send_rst(&mut self, nic: &mut TcpHandle) -> io::Result<()> {
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

        self.send_pkt(nic, Rst, self.send.nxt, 0)?;
        Ok(())
    }

    /// The number of bytes in transit, with no ack just yet
    pub fn num_unacked_bytes(&self) -> u32 {
        self.closed_at
            .unwrap_or(self.send.nxt)
            .wrapping_sub(self.send.una)
    }

    /// The number of bytes in the tx buffer,
    pub fn num_unsend_bytes(&self) -> Option<u32> {
        (self.unacked.len() as u32).checked_sub(self.num_unacked_bytes())
    }

    pub fn on_tick(&mut self, nic: &mut TcpHandle) -> io::Result<()> {
        if let State::FinWait2 | State::TimeWait | State::Closed = self.state {
            // we have shutdown our write side and the other side acked, no need to (re)transmit anything
            return Ok(());
        }

        // etracing::info!("ON TICK: state {:?} una {} nxt {} unacked {:?}",
        //           self.state, self.send.una, self.send.nxt, self.unacked);

        let now = (self.cfg.clock)();
        let waited_for = self
            .timers
            .send_times
            .range(self.send.una..)
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
            let resend = std::cmp::min(self.unacked.len() as u32, self.send.wnd as u32);
            if resend < self.send.wnd as u32 && self.closed {
                // can we include the FIN?
                self.closed_at = Some(self.send.una.wrapping_add(self.unacked.len() as u32));
                self.cong.on_timeout();
                self.send_pkt(nic, Fin, self.send.una, resend as usize)?;
            } else if let State::SynSent = self.state {
                assert_eq!(resend, 0);

                if self.syn_resend_counter >= self.cfg.syn_resent_count {
                    self.closed = true;
                    self.closed_at = Some(self.send.una);
                    self.state = State::Closed;

                    self.closed_with = Some(io::Error::new(
                        io::ErrorKind::ConnectionRefused,
                        "host unreachabke: syn resend count exceeded",
                    ));

                    return Ok(());
                }

                self.syn_resend_counter += 1;
                self.send_pkt(nic, Syn, self.send.una, 0)?;
            } else if let State::SynRcvd = self.state {
                self.send_pkt(nic, SynAck, self.send.una, 0)?;
            } else {
                self.cong.on_timeout();
                self.send_pkt(nic, Ack, self.send.una, resend as usize)?;
            }
        } else {
            loop {
                let Some(num_unsend_bytes) = self.num_unsend_bytes() else {
                    break;
                };

                // we should send new data if we have new data and space in the window
                if num_unsend_bytes == 0 && self.closed_at.is_some() {
                    return Ok(());
                }

                let remaining_window_space = self.remaining_window_space();
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
                    self.closed_at = Some(self.send.una.wrapping_add(self.unacked.len() as u32));

                    // RFC 9293
                    // -> 3.6. Closing a Connection
                    // Case 1:
                    // Local user initiates the close In this case, a FIN segment can be constructed and placed on the outgoing segment queue.
                    // ...
                    self.send_pkt(nic, Fin, self.send.nxt, bytes_to_be_sent as usize)?;
                } else {
                    if num_unsend_bytes == 0 {
                        break;
                    }
                    self.send_pkt(nic, Ack, self.send.nxt, bytes_to_be_sent as usize)?;
                }
            }
        }

        Ok(())
    }

    pub fn on_packet<'a>(&mut self, nic: &mut TcpHandle, pkt: TcpPacket) -> io::Result<Available> {
        // first, check that sequence numbers are valid (RFC 793 S3.3)
        let seqn = pkt.seq_no;
        let mut slen = pkt.content.len() as u32;
        // # virtual syn and fin bytes
        // the first and last byte are not really send as payload, but rather as an indication that the stream
        // starts or ends. This means seq_no is not exactly pck_len defined but with a + 1
        if pkt.flags.fin {
            slen += 1;
        };
        if pkt.flags.syn {
            slen += 1;
        };

        // max allowed recv seq_no
        // -> aka. last byte that will be accepted in the input stream
        let wend = self.recv.nxt.wrapping_add(self.recv.wnd as u32);

        tracing::info!(
            "recv({seqn}, len: {slen} (real {}), wend: {wend})",
            pkt.content.len(),
        );

        // RST handeling
        if pkt.flags.rst {
            // RFC 9293
            // -> 3.5.3. Reset Processing
            // In all states except SYN-SENT, all reset (RST) segments are validated by checking their SEQ fields.
            // A reset is valid if its sequence number is in the window. In the SYN-SENT state
            // (a RST received in response to an initial SYN), the RST is acceptable if the ACK field acknowledges the SYN.
            let valid = if let State::SynSent = self.state {
                true
            } else {
                self.packet_is_valid(slen, seqn, wend, &pkt)
            };

            // RFC 9293
            // -> 3.5.3. Reset Processing
            // The receiver of a RST first validates it, then changes state.
            // If the receiver was in the LISTEN state, it ignores it.
            // If the receiver was in SYN-RECEIVED state and had previously been in the LISTEN state,
            // then the receiver returns to the LISTEN state;
            // otherwise, the receiver aborts the connection and goes to the CLOSED state.
            // If the receiver was in any other state, it aborts the connection and advises the user and goes to the CLOSED state.
            //
            // -> LISTEN does not exist, when a connection object exitst -> NOP
            // -> SYN-RECEIVED to LISTEN is implemented by closing the connection, since the LISTEN socket is a seperate object -> allways CLOSED
            // -> go CLOSED
            if !valid {
                return Ok(Available::empty());
            }

            self.closed = true;
            self.state = State::Closed;

            return Ok(Available::empty());
        }

        let okay = self.packet_is_valid(slen, seqn, wend, &pkt);

        // TODO: explain
        // not okay, try indicating a resend
        if !okay {
            tracing::error!("NOT OKAY");
            self.send_pkt(nic, Ack, self.send.nxt, 0)?;
            return Ok(self.availability());
        }

        // process options, always
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

        // if no-ack but syn, inc recv counter (virtual start byte)
        if !pkt.flags.ack {
            if pkt.flags.syn {
                // got SYN part of initial handshake
                assert!(pkt.content.is_empty());
                self.recv.nxt = seqn.wrapping_add(1);

                if let State::SynRcvd = self.state {
                    // resend SYN ACK, it seems to be lost
                    self.send_pkt(nic, SynAck, self.send.nxt.wrapping_sub(1), 0)?;
                }

                if let State::SynSent = self.state {
                    // simultaneous open
                    // send SYN ACK
                    self.recv.irs = pkt.seq_no;
                    self.recv.nxt = pkt.seq_no.wrapping_add(1);
                    self.recv.wnd = pkt.window;
                    self.recv.up = false;

                    self.send_pkt(nic, SynAck, self.send.nxt, 0)?;
                    self.state = State::SynRcvd;
                }
            }
            return Ok(self.availability());
        }

        // acked some code, expecting all ack from now
        let ackn = pkt.ack_no;

        if let State::SynSent | State::SynRcvd = self.state {
            tracing::info!("SYN RECV: ");
            if is_between_wrapped(
                self.send.una.wrapping_sub(1),
                ackn,
                self.send.nxt.wrapping_add(1),
            ) {
                // must have ACKed our SYN, since we detected at least one acked byte,
                // and we have only sent one byte (the SYN).
                tracing::info!("established connection from ACK");
                // Syn sent behaviour
                if let State::SynSent = self.state {
                    self.recv.irs = pkt.seq_no;
                    self.recv.nxt = self.recv.irs + 1;
                    self.recv.wnd = pkt.window;
                    self.send_pkt(nic, Ack, self.send.nxt, 0)?;

                    self.state = State::Estab;
                }

                self.state = State::Estab;
            } else {
                // TODO: <SEQ=SEG.ACK><CTL=RST>
            }
        }

        // We already have a ack history, so start to tick of from buffers
        if let State::Estab | State::FinWait1 | State::FinWait2 | State::LastAck | State::Closing =
            self.state
        {
            // akc no must be between last_acked ... next
            // -> if not, either not valid or already known ack
            self.send.wnd = pkt.window;
            if is_between_wrapped(self.send.una, ackn, self.send.nxt.wrapping_add(1)) {
                tracing::info!(
                    "ack for {} (last: {}); prune {} bytes",
                    ackn,
                    self.send.una,
                    ackn - self.send.una
                );

                // If unacked is not empty, ack did something actually,
                // TODO: Wake Write
                if !self.unacked.is_empty() {
                    // seq no of lasted unacked byte, corrected for virtual bytes
                    let data_start = if self.send.una == self.send.iss {
                        // send.una hasn't been updated yet with ACK for our SYN, so data starts just beyond it
                        self.send.una.wrapping_add(1)
                    } else {
                        self.send.una
                    };

                    // number of acked bytes, to be drained from the buffer
                    let acked_data_end =
                        std::cmp::min(ackn.wrapping_sub(data_start) as usize, self.unacked.len());
                    self.unacked.drain(..acked_data_end);

                    // We go an ack, reset send timers, we can send once more
                    let old = std::mem::replace(&mut self.timers.send_times, BTreeMap::new());

                    let una = self.send.una;
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

                    let n = ackn - self.send.una;
                    self.cong.on_ack(n, self.send.wnd as u32);
                }

                // set last ack no
                self.send.una = ackn;
            }

            // TODO: if unacked empty and waiting flush, notify
            // TODO: update window
        }

        // Fin wait: I have closed, and send a FIN
        if let State::FinWait1 | State::Closing | State::LastAck = self.state {
            // This should always be true
            if let Some(closed_at) = self.closed_at {
                // we got an ack, check if it is for the FIN
                // since una == FIN seq no (una is final since next will not move, since we are write-closed)
                if self.send.una == closed_at.wrapping_add(1) {
                    // our FIN has been ACKed!
                    let new_state = match self.state {
                        State::FinWait1 => State::FinWait2,
                        State::Closing => State::TimeWait,
                        State::LastAck => State::Closed,
                        _ => unreachable!(),
                    };
                    tracing::info!("received ACK for FIN ({:?} -> {:?})", self.state, new_state);
                    self.state = new_state;
                }
            }
        }

        // Process data in packets
        if !pkt.content.is_empty() {
            // recv open states
            if let State::Estab | State::FinWait1 | State::FinWait2 = self.state {
                // offset of received data to expected data
                // we might get a packet further to the furutre
                // -> never negative, since seq_no was checked
                let mut unread_data_at = self.recv.nxt.wrapping_sub(seqn) as usize;

                // FIN escape hatch
                if unread_data_at > pkt.content.len() {
                    // we must have received a re-transmitted FIN that we have already seen
                    // nxt points to beyond the fin, but the fin is not in data!
                    assert_eq!(unread_data_at, pkt.content.len() + 1);
                    unread_data_at = 0;
                }

                // Extend the incoming data
                self.incoming.extend(&pkt.content[unread_data_at..]);

                // TODO: reordering, current impl only allows in-order

                /*
                Once the TCP takes responsibility for the data it advances
                RCV.NXT over the data accepted, and adjusts RCV.WND as
                apporopriate to the current buffer availability.  The total of
                RCV.NXT and RCV.WND should not be reduced.
                 */
                self.recv.nxt = seqn.wrapping_add(pkt.content.len() as u32);

                // Send an acknowledgment of the form: <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>
                // TODO: maybe just tick to piggyback ack on data?
                self.send_pkt(nic, Ack, self.send.nxt, 0)?;
            }
        }

        // If this is a FIN packet do something
        if pkt.flags.fin {
            match self.state {
                State::FinWait1 => {
                    // simultaneous close
                    tracing::info!("closing recv-duplex due to received FIN (CLOSING)");
                    self.recv.nxt = self.recv.nxt.wrapping_add(1);
                    self.send_pkt(nic, Ack, self.send.nxt, 0)?;
                    self.state = State::Closing;
                }
                State::FinWait2 => {
                    // we're done with the connection!
                    tracing::info!("closing recv-simplex due to received FIN (TIME_WAIT)");
                    self.recv.nxt = self.recv.nxt.wrapping_add(1);
                    self.send_pkt(nic, Ack, self.send.nxt, 0)?;
                    self.state = State::TimeWait;
                }
                State::Estab => {
                    // peer is done with connection
                    tracing::info!("closing recv-simplex due to received FIN (CLOSE_WAIT)");
                    self.recv.nxt = self.recv.nxt.wrapping_add(1);
                    self.send_pkt(nic, Ack, self.send.nxt, 0)?;
                    self.state = State::CloseWait;
                }
                State::CloseWait => {
                    // resend FIN (ACK must be lost)
                    self.send_pkt(nic, Ack, self.send.nxt, 0)?;
                }
                _ => unimplemented!("unknown state for FIN recv: {:?}", self.state),
            }
        }

        Ok(self.availability())
    }

    fn packet_is_valid(&mut self, slen: u32, seqn: u32, wend: u32, pkt: &TcpPacket) -> bool {
        let okay = if slen == 0 {
            // zero-length segment has separate rules for acceptance
            if self.recv.wnd == 0 {
                if seqn != self.recv.nxt {
                    tracing::warn!("not okay: zero-length no window not virtual byte");
                    false
                } else {
                    // allowed if seq_no is not next -> to receive virtual bytes independen of window
                    true
                }
            } else if !is_between_wrapped(self.recv.nxt.wrapping_sub(1), seqn, wend) {
                tracing::warn!("not okay: zero-length not in rnage");
                false
            } else {
                // Else expect valid packet with virtual byte within next+1 ... wend
                true
            }
        } else {
            // When the window is empty, its always invalid to receive another packet
            if self.state == State::SynSent && pkt.flags.syn && pkt.flags.ack {
                true
            } else if self.state == State::SynRcvd && pkt.flags.syn && !pkt.flags.ack {
                true
            } else if self.recv.wnd == 0 {
                tracing::warn!("not okay: non-zero-length empty window");
                // Edge Case: SYN of simultaneous open
                self.state == State::SynSent && pkt.flags.syn && !pkt.flags.ack
            } else if !is_between_wrapped(self.recv.nxt.wrapping_sub(1), seqn, wend)
                && !is_between_wrapped(
                    self.recv.nxt.wrapping_sub(1),
                    seqn.wrapping_add(slen - 1),
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
                self.state = State::FinWait1;
            }
            State::FinWait1 | State::FinWait2 => {}
            State::CloseWait => self.state = State::LastAck,
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
            up: false,
        }
    }

    pub const fn empty() -> Self {
        Self {
            nxt: 0,
            wnd: 0,
            irs: 0,
            up: false,
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

fn is_between_wrapped(start: u32, x: u32, end: u32) -> bool {
    wrapping_lt(start, x) && wrapping_lt(x, end) || start == x
}
