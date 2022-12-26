#![allow(unused)]
use des::prelude::*;
use std::{
    collections::VecDeque,
    net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4},
};

use super::mock::*;

mod buf;
use buf::TcpBuffer;

#[derive(Debug, Clone)]
pub struct TcpController {
    state: TcpState,

    local_addr: SocketAddr,
    peer_addr: SocketAddr,

    last_recv_seq_no: u32,
    total_bytes: usize,
    good_bytes: usize,

    receive_queue: usize,
    send_queue: usize,

    send_buffer: TcpBuffer,
    recv_buffer: TcpBuffer,

    send_bytes: u32,
    ack_bytes: u32,

    last_ack_seq_no: u32,
    next_send_seq_no: u32,
    max_allowed_seq_no: u32,

    congestion_ctrl: bool,

    congestion_window: u32,
    ssthresh: u32,
    congestion_avoid_counter: u32,

    next_send_buffer_seq_no: u32,

    timeout: Duration,
    timewait: Duration,

    timer: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[repr(u8)]
enum TcpState {
    #[default]
    Closed = 0,
    Listen = 1,
    SynSent = 2,
    SynRcvd = 3,
    Established = 4,
    FinWait1 = 5,
    FinWait2 = 6,
    Closing = 7,
    TimeWait = 8,
    CloseWait = 9,
    LastAck = 10,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum TcpPacketId {
    Syn,
    Ack,
    Fin,
}

#[derive(Debug)]
#[non_exhaustive]
enum TcpEvent {
    SysListen(),
    SysOpen(SocketAddr),
    SysClose(),
    SysSend(),
    SysRecv(),

    Syn(NetworkPacket),
    Ack(NetworkPacket),
    Fin(NetworkPacket),
    Data(NetworkPacket),
    Perm(NetworkPacket),

    Timeout(),
}

pub enum TcpSyscall {
    Listen(),
    Open(SocketAddr),
    Close(),
    Send,
    Recv,
}

impl TcpController {
    pub fn new(addr: SocketAddr) -> Self {
        Self {
            state: TcpState::Closed,

            local_addr: addr,
            peer_addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)),

            last_recv_seq_no: 0,
            total_bytes: 0,
            good_bytes: 0,

            receive_queue: 1, // initalize from par
            send_queue: 1,    // initalize from par

            send_bytes: 0,
            ack_bytes: 0,

            send_buffer: TcpBuffer::new(4096),
            recv_buffer: TcpBuffer::new(4096),

            last_ack_seq_no: 0,
            next_send_seq_no: 0,
            max_allowed_seq_no: 0,

            congestion_ctrl: false,

            congestion_window: 1,
            ssthresh: 0,
            congestion_avoid_counter: 0,

            next_send_buffer_seq_no: 0,

            timeout: Duration::from_secs(1),  // from pars.
            timewait: Duration::from_secs(1), // from pars,

            timer: 0,
        }
    }

    pub fn process(&mut self, pkt: NetworkPacket) {
        assert_eq!(pkt.dest, self.local_addr.ip());
        assert_eq!(pkt.dest_port, self.local_addr.port());

        assert!(self.invariants());

        // Missing PERM
        let event = if pkt.flags.syn() {
            TcpEvent::Syn(pkt)
        } else {
            if pkt.flags.fin() {
                TcpEvent::Fin(pkt)
            } else {
                if pkt.data.is_empty() && pkt.flags.ack() {
                    TcpEvent::Ack(pkt)
                } else {
                    TcpEvent::Data(pkt)
                }
            }
        };

        match self.state {
            TcpState::Closed => self.process_state_closed(event),
            TcpState::Listen => self.process_state_listen(event),
            TcpState::SynSent => self.process_state_syn_sent(event),
            TcpState::SynRcvd => self.process_state_syn_rcvd(event),
            TcpState::Established => self.process_state_established(event),
            TcpState::FinWait1 => self.process_state_fin_wait1(event),
            TcpState::FinWait2 => self.process_state_fin_wait2(event),
            TcpState::TimeWait => self.process_state_time_wait(event),
            TcpState::Closing => self.process_state_closing(event),
            TcpState::CloseWait => self.process_state_close_wait(event),
            TcpState::LastAck => self.process_state_last_ack(event),
        }

        assert!(self.invariants());
    }

    pub fn process_timeout(&mut self, msg: Message) {
        if msg.header().id != self.timer {
            return;
        }

        let event = TcpEvent::Timeout();
        match self.state {
            TcpState::Closed => self.process_state_closed(event),
            TcpState::Listen => self.process_state_listen(event),
            TcpState::SynSent => self.process_state_syn_sent(event),
            TcpState::SynRcvd => self.process_state_syn_rcvd(event),
            TcpState::Established => self.process_state_established(event),
            TcpState::FinWait1 => self.process_state_fin_wait1(event),
            TcpState::FinWait2 => self.process_state_fin_wait2(event),
            TcpState::TimeWait => self.process_state_time_wait(event),
            TcpState::Closing => self.process_state_closing(event),
            TcpState::CloseWait => self.process_state_close_wait(event),
            TcpState::LastAck => self.process_state_last_ack(event),
        }
    }

    pub fn syscall(&mut self, syscall: TcpSyscall) {
        let event = match syscall {
            TcpSyscall::Listen() => TcpEvent::SysListen(),
            TcpSyscall::Open(peer) => TcpEvent::SysOpen(peer),
            TcpSyscall::Close() => TcpEvent::SysClose(),
            _ => unimplemented!(),
        };

        match self.state {
            TcpState::Closed => self.process_state_closed(event),
            TcpState::Listen => self.process_state_listen(event),
            TcpState::SynSent => self.process_state_syn_sent(event),
            TcpState::SynRcvd => self.process_state_syn_rcvd(event),
            TcpState::Established => self.process_state_established(event),
            TcpState::FinWait1 => self.process_state_fin_wait1(event),
            TcpState::FinWait2 => self.process_state_fin_wait2(event),
            TcpState::TimeWait => self.process_state_time_wait(event),
            TcpState::Closing => self.process_state_closing(event),
            TcpState::CloseWait => self.process_state_close_wait(event),
            TcpState::LastAck => self.process_state_last_ack(event),
        }
    }

    //

    fn process_state_closed(&mut self, event: TcpEvent) {
        match event {
            TcpEvent::SysListen() => {
                self.state = TcpState::Listen;
                // syscall reply
            }
            TcpEvent::SysOpen(peer) => {
                self.peer_addr = peer;

                self.last_recv_seq_no = 0;
                self.next_send_seq_no = self.select_inital_seq_no();
                self.send_buffer
                    .fwd_to_seq_no(self.next_send_seq_no as usize + 1);
                self.next_send_buffer_seq_no = self.next_send_seq_no + 1;
                self.max_allowed_seq_no = self.next_send_seq_no;

                let mut pkt = self.create_packet(TcpPacketId::Syn, self.next_send_seq_no, 0);
                self.next_send_seq_no += 1;

                pkt.window = self.receive_queue as u16;

                log::info!("[C] Sending SYN {{ seq_no: {} }}", pkt.seq_no);
                send(pkt, "out");
                self.set_timer(self.timeout);

                self.state = TcpState::SynSent;
                // syscall reply
            }
            _ => unimplemented!(),
        }
    }

    fn process_state_listen(&mut self, event: TcpEvent) {
        match event {
            TcpEvent::Syn(syn) => {
                assert!(syn.flags.syn());

                self.peer_addr = SocketAddr::new(syn.src, syn.src_port);

                self.last_recv_seq_no = syn.seq_no;
                self.recv_buffer.fwd_to_seq_no(syn.seq_no as usize + 1);

                self.next_send_seq_no = self.select_inital_seq_no();
                self.send_buffer
                    .fwd_to_seq_no(self.next_send_seq_no as usize + 1);

                self.next_send_buffer_seq_no = self.next_send_seq_no + 1;
                self.max_allowed_seq_no = self.next_send_seq_no + syn.window as u32;

                log::trace!("Window size: {}", syn.window);

                let mut pkt = self.create_packet(
                    TcpPacketId::Syn,
                    self.next_send_seq_no,
                    self.last_recv_seq_no + 1,
                );
                pkt.window = self.receive_queue as u16;
                self.next_send_seq_no += 1;

                log::info!(
                    "[L] Sending SYNACK {{ seq_no: {}, ack: {} }}",
                    pkt.seq_no,
                    pkt.ack_no
                );
                send(pkt, "out");
                self.set_timer(self.timeout);

                // syscall incoming ind.
                self.state = TcpState::SynRcvd;
            }
            TcpEvent::SysClose() => {
                self.state = TcpState::Closed;
                // syscall reply
            }
            _ => unimplemented!("Got: {:?}", event),
        }
    }

    fn process_state_syn_sent(&mut self, event: TcpEvent) {
        match event {
            TcpEvent::Syn(pkt) => {
                self.last_recv_seq_no = pkt.seq_no;
                self.recv_buffer.fwd_to_seq_no(pkt.seq_no as usize + 1);

                if pkt.flags.ack() {
                    self.last_ack_seq_no = pkt.ack_no;
                    self.max_allowed_seq_no = self.last_ack_seq_no + pkt.window as u32 - 1;

                    self.send_ack(self.last_recv_seq_no + 1, self.recv_window());

                    self.cancel_timer();
                    // syscall established ind

                    log::info!(
                        "[SS] Established with Sender {{ seq_no: {}, buf: {}, max_seq_no: {} }} and Receiver {{ last_ack: {} }}",
                        self.next_send_seq_no,
                        self.next_send_buffer_seq_no,
                        self.max_allowed_seq_no,
                        self.last_recv_seq_no
                    );
                    self.state = TcpState::Established;
                } else {
                    log::info!("[SS] -> [SR]");

                    self.send_ack(self.last_recv_seq_no + 1, self.recv_window());
                    self.max_allowed_seq_no = self.last_ack_seq_no + pkt.window as u32 - 1;
                    self.state = TcpState::SynRcvd;
                }
            }
            TcpEvent::Ack(_) => {
                // NOP
            }
            TcpEvent::Timeout() => {
                let pkt = self.create_packet(TcpPacketId::Syn, self.next_send_seq_no - 1, 0);

                log::info!("[L] Re-Sending SYN {{ seq_no: {} }}", pkt.seq_no,);
                send(pkt, "out");
                self.set_timer(self.timeout);
            }
            _ => unimplemented!(),
        }
    }

    fn process_state_syn_rcvd(&mut self, event: TcpEvent) {
        match event {
            TcpEvent::Syn(_) => (),
            TcpEvent::Fin(_) => (),
            TcpEvent::Data(pkt) => {
                // Own addition
                self.last_ack_seq_no = pkt.ack_no;

                if self.last_ack_seq_no - 1 + pkt.window as u32 > self.max_allowed_seq_no {
                    self.max_allowed_seq_no = self.last_ack_seq_no - 1 + pkt.window as u32;
                }

                self.cancel_timer();
                // syscall estab ind
                log::info!(
                    "[SR] Established with Sender {{ seq_no: {}, buf: {}, max_seq_no: {} }} and Receiver {{ last_ack: {} }}",
                    self.next_send_seq_no,
                    self.next_send_buffer_seq_no,
                    self.max_allowed_seq_no,
                    self.last_recv_seq_no
                );

                self.state = TcpState::Established;
                self.handle_data(pkt)
            }
            TcpEvent::Ack(pkt) => {
                self.last_ack_seq_no = pkt.ack_no;

                if self.last_ack_seq_no - 1 + pkt.window as u32 > self.max_allowed_seq_no {
                    self.max_allowed_seq_no = self.last_ack_seq_no - 1 + pkt.window as u32;
                }

                self.cancel_timer();
                // syscall estab ind
                log::info!(
                    "[SR] Established with Sender {{ seq_no: {}, buf: {}, max_seq_no: {} }} and Receiver {{ last_ack: {} }}",
                    self.next_send_seq_no,
                    self.next_send_buffer_seq_no,
                    self.max_allowed_seq_no,
                    self.last_recv_seq_no
                );

                self.state = TcpState::Established;
            }

            TcpEvent::Timeout() => {
                let mut pkt = self.create_packet(
                    TcpPacketId::Syn,
                    self.next_send_seq_no - 1,
                    self.last_recv_seq_no + 1,
                );
                pkt.window = self.recv_window() as u16;

                log::info!(
                    "[L] Re-Sending SYNACK {{ seq_no: {}, ack_no: {} }}",
                    pkt.seq_no,
                    pkt.ack_no
                );
                send(pkt, "out");
                self.set_timer(self.timeout);
            }
            _ => unimplemented!(),
        }
    }

    fn process_state_established(&mut self, event: TcpEvent) {
        match event {
            // TODO
            TcpEvent::SysClose() => {
                let pkt = self.create_packet(
                    TcpPacketId::Fin,
                    self.next_send_seq_no,
                    self.last_recv_seq_no + 1,
                );
                self.next_send_seq_no += 1;
                log::info!("[E] Initialing shutdown with FIN");
                send(pkt, "out");

                self.state = TcpState::FinWait1;
            }
            TcpEvent::Fin(pkt) => {
                log::info!("[E] Got FIN");
                self.last_recv_seq_no = pkt.seq_no;
                self.handle_data(pkt);

                self.send_ack(self.last_recv_seq_no + 1, self.recv_window());
                self.state = TcpState::CloseWait;

                // TODO: Quickfix
                self.syscall(TcpSyscall::Close());
            }
            TcpEvent::Ack(pkt) | TcpEvent::Data(pkt) | TcpEvent::Perm(pkt) => {
                self.handle_data(pkt);
            }
            TcpEvent::Timeout() => {
                self.handle_data_timeout();
            }
            TcpEvent::SysSend() | TcpEvent::SysRecv() => todo!(),

            // Own addition
            TcpEvent::Syn(pkt) => {
                // This is client and the ACK must have been dropped.
            }

            _ => {
                println!("Rejecting {:?}", event)
            }
        }
    }

    fn process_state_fin_wait1(&mut self, event: TcpEvent) {
        // log::trace!("{:?}", event);
        match event {
            TcpEvent::Fin(pkt) => {
                self.last_recv_seq_no = pkt.seq_no;

                if pkt.flags.ack() {
                    self.handle_data(pkt);
                }

                // syscall closing ind
                self.send_ack(self.last_recv_seq_no + 1, self.recv_window());
                self.state = TcpState::Closing;
            }
            TcpEvent::Timeout() => self.handle_data_timeout(),
            TcpEvent::Data(pkt) | TcpEvent::Ack(pkt) | TcpEvent::Perm(pkt) => {
                // let ack_of_fin = pkt.flags.ack() && self.next_send_buffer_seq_no == pkt.ack_no;
                let ack_of_fin = true;
                self.handle_data(pkt);

                if ack_of_fin {
                    self.state = TcpState::FinWait2;
                }
            }
            TcpEvent::SysRecv() => {
                unimplemented!()
            }
            _ => unimplemented!(),
        }
    }

    fn process_state_fin_wait2(&mut self, event: TcpEvent) {
        match event {
            TcpEvent::Fin(pkt) => {
                self.last_recv_seq_no = pkt.seq_no;
                self.handle_data(pkt);

                self.send_ack(self.last_recv_seq_no + 1, self.recv_window());
                // cancel event, timer
                self.set_timer(self.timewait);

                self.state = TcpState::TimeWait;
            }
            TcpEvent::Timeout() => self.handle_data_timeout(),
            TcpEvent::Data(pkt) | TcpEvent::Ack(pkt) | TcpEvent::Perm(pkt) => self.handle_data(pkt),
            TcpEvent::SysRecv() => unimplemented!(),
            _ => unimplemented!(),
        }
    }

    fn process_state_closing(&mut self, event: TcpEvent) {
        match event {
            TcpEvent::Timeout() => self.handle_data_timeout(),
            TcpEvent::Ack(pkt) | TcpEvent::Perm(pkt) => {
                let ack_of_fin = pkt.flags.ack() && self.next_send_buffer_seq_no == pkt.ack_no;
                self.handle_data(pkt);

                if ack_of_fin {
                    // cancel timer
                    self.set_timer(self.timewait);
                    self.state = TcpState::TimeWait;
                }
            }
            TcpEvent::SysRecv() => unimplemented!(),
            TcpEvent::SysOpen(_) | TcpEvent::SysListen() => unimplemented!(),
            _ => unimplemented!(),
        }
    }

    fn process_state_time_wait(&mut self, event: TcpEvent) {
        match event {
            TcpEvent::Timeout() => {
                self.reset_connection_pars();

                log::info!("Closed");
                self.state = TcpState::Closed;
            }
            TcpEvent::SysRecv() => unimplemented!(),
            TcpEvent::SysOpen(_) | TcpEvent::SysListen() => unimplemented!(),
            _ => unimplemented!(),
        }
    }

    fn process_state_close_wait(&mut self, event: TcpEvent) {
        match event {
            TcpEvent::Timeout() => self.handle_data_timeout(),
            TcpEvent::SysClose() => {
                // self.last_recv_seq_no = pkt.seq_no;
                // self.handle_data(pkt);

                self.send_ack(self.last_recv_seq_no + 1, self.recv_window());

                let pkt = self.create_packet(TcpPacketId::Fin, self.next_send_seq_no, 0);
                send_in(pkt, "out", Duration::from_millis(50));

                self.state = TcpState::LastAck;
            }
            _ => unimplemented!(),
        }
    }

    fn process_state_last_ack(&mut self, event: TcpEvent) {
        match event {
            TcpEvent::Ack(pkt) => {
                self.reset_connection_pars();
                self.state = TcpState::Closed;
            }
            _ => unimplemented!(),
        }
    }
}

impl TcpController {
    fn handle_data(&mut self, pkt: NetworkPacket) {
        log::debug!(
            "Data {{ ack: {}, max: {}, seq: {}, buf: {} }} with Packet {{ seq_no: {}, ack_no: {}, data: {} }}",
            self.last_ack_seq_no,
            self.max_allowed_seq_no,
            self.next_send_seq_no,
            self.next_send_buffer_seq_no,
            pkt.seq_no,
            pkt.ack_no,
            pkt.data.len()
        );

        if pkt.flags.ack() {
            // let buf_full = self.send_queue == self.send_buffer.size();
            let buf_full = self.send_buffer.remaining_cap() == 0;

            self.cancel_timer();
            if self.last_ack_seq_no < pkt.ack_no - 1 {
                let n = pkt.ack_no - self.last_ack_seq_no;
                self.send_buffer.free(n as usize);

                // freeBuffers
                self.last_ack_seq_no = pkt.ack_no;

                if self.last_ack_seq_no < self.next_send_seq_no {
                    self.set_data_timer()
                } else {
                    // opti
                    self.next_send_seq_no = self.last_ack_seq_no;
                }

                if self.congestion_ctrl {
                    if self.congestion_window < self.ssthresh {
                        self.congestion_window += 1;
                        self.congestion_avoid_counter = self.congestion_window;
                    } else {
                        self.congestion_avoid_counter.saturating_sub(1);
                        if self.congestion_avoid_counter == 0 {
                            self.congestion_window += 1;
                            self.congestion_avoid_counter = self.congestion_window;
                        }
                    }
                }

                if buf_full {
                    // SysStopInd
                }
            }

            self.max_allowed_seq_no = self.last_ack_seq_no - 1 + pkt.window as u32;
            self.do_sending()
        }

        if !pkt.data.is_empty() {
            log::trace!("{{DATA}} Got Packet {{ seq_no: {} }}", pkt.seq_no);

            // if permit sched, remove
            // TODO
            if self.receive_queue - 0 > 0 {
                self.recv_buffer.write_to(&pkt.data, pkt.seq_no as usize);
                // self.recv_buffer.write_to_head(&pkt.data);
                self.last_recv_seq_no = pkt.seq_no + pkt.data.len() as u32;

                self.send_ack(
                    pkt.seq_no + pkt.data.len() as u32,
                    self.receive_queue as u16 - 0,
                );
            }
        }
    }

    fn do_sending(&mut self) {
        // log::debug!(
        //     "{{DOSENDING}} ack: {}, max: {}, seq: {}, buf: {}",
        //     self.last_ack_seq_no,
        //     self.max_allowed_seq_no,
        //     self.next_send_seq_no,
        //     self.next_send_buffer_seq_no
        // );

        // FIN may be send without window
        if self.max_allowed_seq_no == self.next_send_buffer_seq_no.saturating_sub(2) && true {
            self.max_allowed_seq_no += 1;
        }

        assert!(self.invariants());

        let max_seq_no = if self.congestion_ctrl {
            self.max_allowed_seq_no
                .min(self.last_ack_seq_no - 1 + self.congestion_window)
        } else {
            self.max_allowed_seq_no
        };

        let mut offset = 0;
        while self.next_send_seq_no <= max_seq_no
            && self.next_send_seq_no < self.next_send_buffer_seq_no
        {
            // send buffer set timeout
            // reschedule timer
            // get_data_packet
            // send

            self.set_data_timer();

            let mut buf = vec![0u8; 1024];
            let n = self.send_buffer.peek_relative(&mut buf, offset);
            buf.truncate(n);
            offset += n;

            let pkt = NetworkPacket {
                src: self.local_addr.ip(),
                dest: self.peer_addr.ip(),
                src_port: self.local_addr.port(),
                dest_port: self.peer_addr.port(),
                seq_no: self.next_send_seq_no,
                ack_no: self.last_recv_seq_no,
                offset: 0,
                flags: TcpControlFlags::new().set_ack(true),
                window: self.recv_window(),
                checksum: 0,
                urgent_ptr: 0,
                data: buf,
            };

            self.next_send_seq_no += n as u32;

            log::trace!(
                "Sending Packet {{ seq_no {} ack_no {} data: {} }}",
                pkt.seq_no,
                pkt.ack_no,
                pkt.data.len()
            );
            send(pkt, "out")
        }

        assert!(self.invariants());
    }

    fn set_data_timer(&mut self) {
        // log::debug!("Setting data timer");
        self.timer += 1;
        schedule_in(
            Message::new().kind(u16::MAX).id(self.timer).build(),
            self.timeout,
        );
    }

    fn cancel_timer(&mut self) {
        self.timer += 1;
    }

    pub fn send_data(&mut self, pkt: &[u8], nowin: bool) -> usize {
        // TODO:
        let n = self.send_buffer.write_to_head(pkt);
        self.next_send_buffer_seq_no += n as u32;
        self.do_sending();
        n
    }

    pub fn read_data(&mut self, buf: &mut [u8]) -> usize {
        let n = self.recv_buffer.peek_relative(buf, 0);
        self.recv_buffer.free(n);
        n
    }

    pub fn close(&mut self) {}

    fn handle_data_timeout(&mut self) {
        log::trace!("DATA TIMEOUT");
        // TODO: Handle permit packets
        self.next_send_seq_no = self.last_ack_seq_no;
        // self.set_data_timer();

        self.do_sending();
    }

    fn send_ack(&mut self, next_expected: u32, win: u16) {
        assert!(next_expected > 0);
        let mut ack =
            self.create_packet(TcpPacketId::Ack, self.next_send_seq_no - 1, next_expected);
        if win > 0 {
            ack.window = win;
        }
        send(ack, "out")
    }

    fn send_buffer_len(&self) -> u32 {
        self.next_send_buffer_seq_no - self.next_send_seq_no
    }

    fn send_window(&self) -> u32 {
        self.max_allowed_seq_no - (self.next_send_seq_no - 1)
    }

    fn recv_window(&self) -> u16 {
        (self.recv_buffer.cap() - self.recv_buffer.len()) as u16
    }

    fn invariants(&self) -> bool {
        // if matches!(self.state, TcpState::Closed | TcpState::Listen) {
        // if self.state == TcpState::SynSent {
        // if self.state as u8 >= TcpState::SynSent as u8 {
        // if self.state as u8 >= TcpState::SynRcvd as u8 {

        // if self.state as u8 == TcpState::Established as u8 {
        //     assert!(self.last_ack_seq_no <= self.next_send_seq_no);
        //     assert!(self.next_send_seq_no <= self.next_send_buffer_seq_no);
        //     assert!(self.next_send_seq_no <= self.max_allowed_seq_no + 1);
        //     assert!(self.last_ack_seq_no - 1 <= self.max_allowed_seq_no);

        //     if self.congestion_ctrl {
        //         assert!(self.next_send_seq_no <= self.last_ack_seq_no + self.congestion_window);
        //         assert!(
        //             self.congestion_window <= self.ssthresh && self.congestion_avoid_counter > 0
        //         );
        //     }
        // }

        true
    }

    fn create_packet(&self, id: TcpPacketId, seq_no: u32, expected: u32) -> NetworkPacket {
        let ack = expected != 0 || id == TcpPacketId::Ack;
        let syn = id == TcpPacketId::Syn;
        let fin = id == TcpPacketId::Fin;

        NetworkPacket {
            src: self.local_addr.ip(),
            dest: self.peer_addr.ip(),
            src_port: self.local_addr.port(),
            dest_port: self.peer_addr.port(),
            seq_no,
            ack_no: expected,
            offset: 0,
            flags: TcpControlFlags::new()
                .set_ack(ack)
                .set_syn(syn)
                .set_fin(fin),
            window: 0,
            checksum: 0,
            urgent_ptr: 0,
            data: Vec::new(),
        }
    }

    fn set_timer(&mut self, expiration: Duration) {
        // log::debug!("Setting normal timer");
        schedule_in(
            Message::new().kind(u16::MAX).id(self.timer).build(),
            expiration,
        )
    }

    fn reset_connection_pars(&mut self) {
        self.state = TcpState::Closed;

        self.local_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
        self.peer_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);

        self.last_ack_seq_no = 0;
        self.next_send_seq_no = 0;
        self.next_send_buffer_seq_no = 0;

        self.last_recv_seq_no = 0;
        self.max_allowed_seq_no = 0;

        self.congestion_window = 1;
        self.congestion_avoid_counter = 0;
    }

    fn select_inital_seq_no(&self) -> u32 {
        100
    }

    pub fn current_state_print(&self) {
        log::trace!(
            "{:?}: Send {{ seq_no: {} buf_no: {}, max_no: {}, acked: {} }} and Recv {{ seq_no: {}, data: {} }}",
            self.state,
            self.next_send_seq_no,
            self.next_send_buffer_seq_no,
            self.max_allowed_seq_no,
            self.last_ack_seq_no,
            self.last_recv_seq_no,
            self.recv_buffer.len()
        );
    }
}
