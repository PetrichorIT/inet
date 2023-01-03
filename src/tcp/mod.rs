//! TCP utility types.
#![allow(unused)]

use std::{
    io::{Result, Error, ErrorKind},
    collections::VecDeque,
    net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4},
    time::Duration, task::Waker,
};

mod pkt;
use des::prelude::{schedule_in, GateRef, Message};
pub use pkt::*;

mod buf;
pub use buf::*;

mod types;
use types::*;

pub(super) mod api;
pub use api::{OwnedReadHalf, OwnedWriteHalf, ReadHalf, WriteHalf, ReuniteError};
use api::*;

mod interest;
use interest::*;

mod debug;
pub use debug::*;

use crate::{
    ip::{IpPacket, IpPacketRef, Ipv4Packet, IpVersion,Ipv4Flags, Ipv6Packet},
    FromBytestream, IntoBytestream, bsd::Fd,
};

use super::{IOContext, KIND_IO_TIMEOUT};

pub(super) const PROTO_TCP: u8 = 0x06;

#[derive(Debug)]
pub(crate) struct TcpController {
    // # General
    state: TcpState,
    local_addr: SocketAddr,
    peer_addr: SocketAddr,
    dropped: bool,

    // # Handshake
    syn_resend_counter: usize,

    // # Send buffer
    sender_buffer: TcpBuffer,
    sender_segments: VecDeque<TcpSegment>,
    sender_queue: VecDeque<IpPacket>,
    sender_last_ack_seq_no: u32,
    sender_next_send_seq_no: u32,
    sender_next_send_buffer_seq_no: u32,
    sender_max_send_seq_no: u32,
    sender_write_interests: Vec<TcpInterestGuard>,

    // # Recv buffer
    receiver_buffer: TcpBuffer,
    receiver_last_recv_seq_no: u32,
    receiver_read_interests: Vec<TcpInterestGuard>,

    // # Congestions
    congestion_ctrl: bool,
    congestion_window: u32,
    ssthresh: u32,
    congestion_avoid_counter: u32,

    // # Parameters
    timeout: Duration,
    timewait: Duration,
    timer: u16,
    fd: Fd,
    inital_seq_no: u32,
    mtu: u16,
    ttl: u8,

    // # Metrics
    sender_send_bytes: usize,
    sender_ack_bytes: usize,

    // # Interest
    established_interest: Option<Waker>,
}

impl TcpController {
    pub fn new(fd: Fd, addr: SocketAddr, config: TcpSocketConfig) -> Self {
        inet_trace!(
            "tcp::create '0x{:x} with buffers {} (sender) {} (recv) at seq_no {} at ttl {}",
            fd,
            config.send_buffer_size,
            config.recv_buffer_size,
            config.inital_seq_no,
            config.ttl,
        );
        Self {
            state: TcpState::Closed,
            dropped: false,
            local_addr: addr,
            peer_addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)),

            syn_resend_counter: 0,

            sender_buffer: TcpBuffer::new(config.send_buffer_size as usize, 0),
            sender_segments: VecDeque::new(),
            sender_queue: VecDeque::new(),
            sender_last_ack_seq_no: 0,
            sender_next_send_seq_no: 0,
            sender_next_send_buffer_seq_no: 0,
            sender_max_send_seq_no: 0,
            sender_write_interests: Vec::new(),

            receiver_buffer: TcpBuffer::new(config.send_buffer_size as usize, 0),
            receiver_last_recv_seq_no: 0,
            receiver_read_interests: Vec::new(),

            congestion_ctrl: false,
            congestion_window: 1,
            ssthresh: 0,
            congestion_avoid_counter: 0,

            timeout: Duration::from_secs(1),
            timewait: Duration::from_secs(1),
            timer: 0,
            fd,
            inital_seq_no: config.inital_seq_no,
            mtu: config.maximum_segment_size,
            ttl: config.ttl as u8,

            sender_send_bytes: 0,
            sender_ack_bytes: 0,

            established_interest: None,
        }
    }
}

impl IOContext {
    pub(super) fn capture_tcp_packet(
        &mut self,
        packet: IpPacketRef,
        last_gate: Option<GateRef>,
    ) -> bool {
        assert!(packet.tos() == PROTO_TCP);

        let Ok(tcp) = TcpPacket::from_buffer(packet.content()) else {
            log::error!("received ip-packet with proto=0x06 (tcp) but content was no tcp-packet");
            return false;
        };

        let src = SocketAddr::new(packet.src(), tcp.src_port);
        let dest = SocketAddr::new(packet.dest(), tcp.dest_port);

        let Some(ifid) = self.get_interface_for_ip_packet(packet.dest(), last_gate).pop() else {
            return false
        };

        let Some((fd, _)) = self.tcp_manager.iter().find(|(_, socket)| socket.local_addr == dest && socket.peer_addr == src) else {
            // may still be a SYN
            let Some((_, listeners)) = self.tcp_listeners.iter_mut().find(|(_, list)| list.local_addr == dest) else {
                return false;
            };
            
            listeners.incoming.push_back(TcpListenerPendingConnection {
                local_addr: listeners.local_addr,
                peer_addr: src,
                packet: (packet.src(), packet.dest(), tcp),
            });

            // Wake up
            let mut i = 0;
            while i < listeners.interests.len() {
                if matches!(listeners.interests[i].interest, TcpInterest::TcpAccept(_)) {
                    let w = listeners.interests.swap_remove(i);
                    w.waker.wake();
                } else {
                    i += 1;
                }
            }

            return true
        };

        let socket = self.sockets.get(fd).expect("underlying os socket dropped");

        if socket.interface != ifid {
            return false;
        }

        self.process(*fd, packet, tcp);

        true
    }

    pub(crate) fn tcp_send_packet(&mut self, ctrl: &mut TcpController, ip: IpPacket) {
        
        ctrl.sender_queue.push_back(ip);

        let Some(socket) = self.sockets.get(&ctrl.fd) else { return };
        let Some(interface) = self.interfaces.get_mut(&socket.interface) else { return };

        if !interface.is_busy() {
            interface
                .send_ip(ctrl.sender_queue.pop_front().unwrap())
                .unwrap();
        } else {
            interface.add_write_interest(ctrl.fd);
        }
    }

    pub(crate) fn tcp_socket_link_update(&mut self, fd: Fd) {
        let Some(ctrl) = self.tcp_manager.get_mut(&fd) else {
            return;
        };

        let Some(socket) = self.sockets.get(&ctrl.fd) else { return };
        let Some(interface) = self.interfaces.get_mut(&socket.interface) else { return };

        if !interface.is_busy() {
            interface
                .send_ip(ctrl.sender_queue.pop_front().unwrap())
                .unwrap();
            
            if !ctrl.sender_queue.is_empty() {
                interface.add_write_interest(ctrl.fd);
            }
        }
    }
}

impl IOContext {
    pub(super) fn process(&mut self, fd: Fd, ip: IpPacketRef<'_, '_>, pkt: TcpPacket) {
        let Some(mut ctrl) = self.tcp_manager.remove(&fd) else {
            return
        };

        assert_eq!(ip.dest(), ctrl.local_addr.ip());
        assert_eq!(pkt.dest_port, ctrl.local_addr.port());

        // Missing PERM
        let event = if pkt.flags.syn {
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

        if ctrl.state == TcpState::Closed && ctrl.dropped {
            inet_trace!("tcp::drop '0x{:x} dropping socket", fd);
            self.bsd_close_socket(fd);
        } else {
            self.tcp_manager.insert(fd, ctrl);
        }
    }

    pub(super)  fn process_timeout(&mut self, fd: Fd, msg: Message) {
        let Some(mut ctrl) = self.tcp_manager.remove(&fd) else {
            return
        };

        // TODO: this extra if should not be nessecary
        // if ctrl.state != TcpState::TimeWait {
            if msg.header().id != ctrl.timer {
                self.tcp_manager.insert(fd, ctrl);
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

        if ctrl.state == TcpState::Closed && ctrl.dropped {
            inet_trace!("tcp::drop '0x{:x} dropping socket", fd);
            self.bsd_close_socket(fd);
        } else {
            self.tcp_manager.insert(fd, ctrl);
        }
    }

    pub(super) fn syscall(&mut self, fd: Fd, syscall: TcpSyscall) {
        let Some(mut ctrl) = self.tcp_manager.remove(&fd) else {
            return
        };
        let event = match syscall {
            TcpSyscall::Listen() => TcpEvent::SysListen(),
            TcpSyscall::Open(peer) => TcpEvent::SysOpen(peer),
            TcpSyscall::Close() => {
                ctrl.dropped = true;
                TcpEvent::SysClose()
            },
            _ => unimplemented!(),
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

        if ctrl.state == TcpState::Closed && ctrl.dropped {
            inet_trace!("tcp::drop '0x{:x} dropping socket", fd);
            self.bsd_close_socket(fd);
        } else {
            self.tcp_manager.insert(fd, ctrl);
        }
    }

    //

    fn process_state_closed(&mut self, ctrl: &mut TcpController, event: TcpEvent) {
        match event {
            TcpEvent::SysListen() => {
                ctrl.state = TcpState::Listen;
                // syscall reply
            }
            TcpEvent::SysOpen(peer) => {
                ctrl.peer_addr = peer;
                self.bsd_bind_peer(ctrl.fd, peer);

                ctrl.syn_resend_counter = 0;
                ctrl.receiver_last_recv_seq_no = 0;
                ctrl.sender_next_send_seq_no = ctrl.inital_seq_no;
                ctrl.sender_buffer
                    .fwd_to_seq_no(ctrl.sender_next_send_seq_no + 1);
                // ctrl.next_send_buffer_seq_no = self.next_send_seq_no + 1; TODO
                ctrl.sender_max_send_seq_no = ctrl.sender_next_send_seq_no;

                let mut pkt = ctrl.create_packet(TcpPacketId::Syn, ctrl.sender_next_send_seq_no, 0);
                pkt.options = ctrl.syn_options();
                ctrl.sender_next_send_seq_no += 1;

                pkt.window = ctrl.recv_window();

                inet_trace!("tcp::closed '0x{:x} Sending SYN {{ seq_no: {} }}", ctrl.fd, pkt.seq_no);
                self.tcp_send_packet(
                    ctrl,
                    ctrl.ip_packet_for(pkt)
                );

                ctrl.set_timer(ctrl.timeout);

                ctrl.state = TcpState::SynSent;
                // syscall reply
            }
            _ => unimplemented!(),
        }
    }

    fn process_state_listen(&mut self, ctrl: &mut TcpController, event: TcpEvent) {
        match event {
            TcpEvent::Syn((src, dest, syn)) => {
                assert!(syn.flags.syn);

                ctrl.peer_addr = SocketAddr::new(src, syn.src_port);

                ctrl.receiver_last_recv_seq_no = syn.seq_no;
                ctrl.receiver_buffer.fwd_to_seq_no(syn.seq_no + 1);

                ctrl.sender_next_send_seq_no = ctrl.inital_seq_no;
                ctrl.sender_buffer
                    .fwd_to_seq_no(ctrl.sender_next_send_seq_no + 1);

                ctrl.sender_next_send_buffer_seq_no = ctrl.sender_next_send_seq_no + 1; 
                ctrl.sender_max_send_seq_no = ctrl.sender_next_send_seq_no + syn.window as u32;
                ctrl.apply_syn_options(&syn.options);

                inet_trace!("tcp::listen '0x{:x} window size: {}", ctrl.fd, syn.window);

                let mut pkt = ctrl.create_packet(
                    TcpPacketId::Syn,
                    ctrl.sender_next_send_seq_no,
                    ctrl.receiver_last_recv_seq_no + 1,
                );
                pkt.options = ctrl.syn_options();
                pkt.window = ctrl.recv_window();
                ctrl.sender_next_send_seq_no += 1;

                inet_trace!(
                    "tcp::listen '0x{:x} Sending SYNACK {{ seq_no: {}, ack: {} }}",
                    ctrl.fd,
                    pkt.seq_no,
                    pkt.ack_no
                );
                self.tcp_send_packet(
                    ctrl,
                    ctrl.ip_packet_for(pkt)
                );
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

    fn process_state_syn_sent(&mut self, ctrl: &mut TcpController, event: TcpEvent) {
        match event {
            TcpEvent::Syn((src, dest, pkt)) => {
                ctrl.receiver_last_recv_seq_no = pkt.seq_no;
                ctrl.receiver_buffer.fwd_to_seq_no(pkt.seq_no + 1);
                ctrl.apply_syn_options(&pkt.options);

                if pkt.flags.ack {
                    ctrl.sender_last_ack_seq_no = pkt.ack_no;
                    ctrl.sender_next_send_buffer_seq_no = ctrl.sender_next_send_seq_no;
                    ctrl.sender_max_send_seq_no =
                        pkt.ack_no + pkt.window as u32; // 

                    self.send_ack(ctrl, ctrl.receiver_last_recv_seq_no + 1, ctrl.recv_window());

                    ctrl.cancel_timer();
                    // syscall established ind

                    inet_trace!(
                        "tcp::synsent '0x{:x} Established with Sender {{ last_ack: {}, seq_no: {}, buf: {},  max_seq_no: {} }} and Receiver {{ last_recv: {} }}",
                        ctrl.fd,
                        ctrl.sender_last_ack_seq_no,
                        ctrl.sender_next_send_seq_no,
                        ctrl.sender_next_send_buffer_seq_no,
                        ctrl.sender_max_send_seq_no,
                        ctrl.receiver_last_recv_seq_no
                    );
                    ctrl.state = TcpState::Established;
                    ctrl.established_interest.take().map(|v| v.wake());
                } else {
                    inet_trace!("tcp::synsent '0x{:x} transition to tcp::synrecv", ctrl.fd);

                    self.send_ack(ctrl, ctrl.receiver_last_recv_seq_no + 1, ctrl.recv_window());
                    ctrl.sender_max_send_seq_no =
                        ctrl.sender_last_ack_seq_no + pkt.window as u32;
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
                    ctrl.established_interest.take().map(|g| g.wake());
                    return;
                }

                let pkt = ctrl.create_packet(TcpPacketId::Syn, ctrl.sender_next_send_seq_no - 1, 0);

                inet_trace!("tcp::synsent '0x{:x} Re-Sending SYN {{ seq_no: {} }}", ctrl.fd, pkt.seq_no,);
                self.tcp_send_packet(
                    ctrl, 
                    ctrl.ip_packet_for(pkt)
                );
                ctrl.set_timer(ctrl.timeout);
            }
            _ => unimplemented!(),
        }
    }

    fn process_state_syn_rcvd(&mut self, ctrl: &mut TcpController, event: TcpEvent) {
        match event {
            TcpEvent::Syn(_) => (),
            TcpEvent::Fin( _) => (),
            TcpEvent::Data((src, dest, pkt)) => {
                // Own addition
                ctrl.sender_last_ack_seq_no = pkt.ack_no;

                if ctrl.sender_last_ack_seq_no - 1 + pkt.window as u32 > ctrl.sender_max_send_seq_no
                {
                    ctrl.sender_max_send_seq_no =
                        pkt.ack_no + pkt.window as u32;
                }

                ctrl.cancel_timer();
                // syscall estab ind
                inet_trace!(
                    "tcp::synrecv '0x{:x} Established with Sender {{ seq_no: {}, buf: {}, max_seq_no: {} }} and Receiver {{ last_ack: {} }}",
                    ctrl.fd,
                    ctrl.sender_next_send_seq_no,
                    ctrl.sender_next_send_buffer_seq_no,
                    ctrl.sender_max_send_seq_no,
                    ctrl.receiver_last_recv_seq_no
                );

                ctrl.state = TcpState::Established;
                ctrl.established_interest.take().map(|v| v.wake());

                self.handle_data(ctrl, src, dest, pkt)
            }
            TcpEvent::Ack((src, dest, pkt)) => {
                ctrl.sender_last_ack_seq_no = pkt.ack_no;

                if ctrl.sender_last_ack_seq_no - 1 + pkt.window as u32 > ctrl.sender_max_send_seq_no
                {
                    ctrl.sender_max_send_seq_no =
                        pkt.ack_no + pkt.window as u32;
                }

                ctrl.cancel_timer();
                // syscall estab ind
                inet_trace!(
                    "tcp::synrecv '0x{:x} Established with Sender {{ seq_no: {}, buf: {}, max_seq_no: {} }} and Receiver {{ last_ack: {} }}",
                    ctrl.fd,
                    ctrl.sender_next_send_seq_no,
                    ctrl.sender_next_send_buffer_seq_no,
                    ctrl.sender_max_send_seq_no,
                    ctrl.receiver_last_recv_seq_no
                );

                ctrl.state = TcpState::Established;
                ctrl.established_interest.take().map(|v| v.wake());
            }

            TcpEvent::Timeout() => {
                let mut pkt = ctrl.create_packet(
                    TcpPacketId::Syn,
                    ctrl.sender_next_send_seq_no - 1,
                    ctrl.receiver_last_recv_seq_no + 1,
                );
                pkt.window = ctrl.recv_window();

                inet_trace!(
                    "tcp::synrecv '0x{:x} Re-Sending SYNACK {{ seq_no: {}, ack_no: {} }}",
                    ctrl.fd,
                    pkt.seq_no,
                    pkt.ack_no
                );
                
                self.tcp_send_packet(
                    ctrl, 
                    ctrl.ip_packet_for(pkt)
                );

                ctrl.set_timer(ctrl.timeout);
            }
            _ => unimplemented!(),
        }
    }

    fn process_state_established(&mut self, ctrl: &mut TcpController, event: TcpEvent) {
        match event {
            TcpEvent::SysClose() => {
                // Handle dropped
                // Active close - consider self client
                // -> self will not read from the recv_buffer any longer
                // -> self must still ack the data send by the server, but no more windows
                // -> self may posses data in the send buffer that must still be send.

                // (0) Send a FIN with seq_no = next_expected
                inet_trace!("tcp::estab '0x{:x} Initialing shutdown with FIN", ctrl.fd);
                let pkt = ctrl.create_packet(
                    TcpPacketId::Fin,
                    ctrl.sender_next_send_seq_no,
                    ctrl.receiver_last_recv_seq_no,
                );
                ctrl.sender_next_send_seq_no += 1;
                self.tcp_send_packet(
                    ctrl, 
                    ctrl.ip_packet_for(pkt)
                );

                // (1) Switch to FinWait1 expecting ACK of FIN
                ctrl.state = TcpState::FinWait1;
            }
            TcpEvent::Fin((src, dest, pkt)) => {
                // Peer initated close
                // Responsder close - consider self server
                // -> Peer will no longer receive data
                // -> Peer may still send data

                // (0) Handle last ack from FINACK packet
                inet_trace!("tcp::estab '0x{:x} Got FIN", ctrl.fd);
                ctrl.receiver_last_recv_seq_no = pkt.seq_no;
                self.handle_data(ctrl, src, dest, pkt);

                // (1) Acknowledge FIN
                self.send_ack(ctrl, ctrl.receiver_last_recv_seq_no + 1, ctrl.recv_window());
                ctrl.state = TcpState::CloseWait;

                // (2) Own FIN means that recv buffer will no longer be used
                // -> Wake all interest so that they can fail with 0
                ctrl.receiver_read_interests.drain(..).for_each(|g| g.wake());

                // // (2) Wait for application close
                // // -> TODO: remove this quickfix
                // self.process_state_close_wait(ctrl, TcpEvent::SysClose());
            }
            TcpEvent::Ack((src, dest, pkt)) | TcpEvent::Data((src, dest, pkt)) | TcpEvent::Perm((src, dest, pkt)) => {
                self.handle_data(ctrl, src,dest, pkt);
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
                println!("Rejecting {:?}", event)
            }
        }
    }


    fn process_state_fin_wait1(&mut self, ctrl: &mut TcpController, event: TcpEvent) {
        // Consider self client
        match event {
            TcpEvent::Fin((src, dest, pkt)) => {
                // Got FIN from server before ACK of FIN
                // Simultaneous Close
                // -> Both sides will no longer receive data
                // -> Both sides may try to send data, can be ignored

                // (0) Handle last ACK from FINACK
                inet_trace!("tcp::finwait1 '0x{:x} received FIN -> simultaneous close", ctrl.fd);
                ctrl.receiver_last_recv_seq_no = pkt.seq_no;
                if pkt.flags.ack {
                    self.handle_data(ctrl, src,dest, pkt);
                }

                // (1) Acknowledge FIN (peer will do the same)
                self.send_ack(ctrl, ctrl.receiver_last_recv_seq_no + 1, ctrl.recv_window());

                // (2) Wait for peer FIN acknowledge
                ctrl.state = TcpState::Closing;
            }
            TcpEvent::Timeout() => {
                // self is client - so data may need to be send before close.
                self.handle_data_timeout(ctrl)
            },
            TcpEvent::Data((src, dest, pkt)) | TcpEvent::Ack((src, dest, pkt)) | TcpEvent::Perm((src, dest, pkt)) => {
                // Got ACK from server
                // -> may be data packet, could be ingored 
                // -> may be ack of data packet, handle
                // -> may be ACK of FIN
                
                // (0) Check for ACK of FIN (seq_no = nss + 1)
                let ack_of_fin = pkt.flags.ack && pkt.ack_no == ctrl.sender_next_send_seq_no;
                if ack_of_fin {
                    // (1) Switch to finwait2 to prevent simultaneous close
                    // -> Since ACK of FIN was send before FIN peer must be in estab
                    // thus now close_wait 
                    inet_trace!("tcp::finwait1 '0x{:x} got ACK of FIN {}", ctrl.fd, pkt.ack_no);
                    ctrl.state = TcpState::FinWait2;
                } else {
                    self.handle_data(ctrl, src,dest, pkt);
                }
            }
            TcpEvent::SysRecv() => {
                unimplemented!()
            }
            _ => unimplemented!(),
        }
    }

    fn process_state_fin_wait2(&mut self, ctrl: &mut TcpController, event: TcpEvent) {
        // consider self client
        // consider non-simultaneous close
        match event {
            TcpEvent::Fin((src,dest, pkt)) => {
                // Active close
                // Wait for FIN indicating that server has decided to close.

                // (0) Handle last ACK of FINACK
                inet_trace!("tcp::finwait2 '0x{:x} going to time-wait", ctrl.fd);
                ctrl.receiver_last_recv_seq_no = pkt.seq_no;
                
                // (1) Send ACK for FIN
                self.send_ack(ctrl, ctrl.receiver_last_recv_seq_no, ctrl.recv_window());
                ctrl.set_timer(ctrl.timewait);

                // (2) Switch to Time-Wait to handle timeouts for final ACKs
                ctrl.state = TcpState::TimeWait;
            }
            TcpEvent::Timeout() => self.handle_data_timeout(ctrl),
            TcpEvent::Data((src,dest, pkt)) | TcpEvent::Ack((src,dest, pkt)) | TcpEvent::Perm((src,dest, pkt)) => {
                // Since server has not yet been closed, data may be send
                self.handle_data(ctrl, src, dest, pkt)
            }
            TcpEvent::SysRecv() => unimplemented!(),
            _ => unimplemented!(),
        }
    }

    fn process_state_closing(&mut self, ctrl: &mut TcpController, event: TcpEvent) {
        // consider self client or server (both client believe)
        // both parties send FIN, expect ACK
        match event {
            TcpEvent::Timeout() => {
                // Both parties closed -> no data 
                // -> but ack resend may be nessecary
                self.handle_data_timeout(ctrl)
            },
            TcpEvent::Ack((src,dest, pkt)) | TcpEvent::Perm((src,dest, pkt)) => {
                // (0) Ignore data parts of packets --> no need for receivers
                
                // (1) Check for ACK of FIN
                let ack_of_fin = pkt.flags.ack && ctrl.sender_next_send_seq_no == pkt.ack_no;
                if ack_of_fin {
                    inet_trace!("tcp::closing '0x{:x} got ACK of FIN {}", ctrl.fd, pkt.ack_no);
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

    fn process_state_time_wait(&mut self, ctrl: &mut TcpController, event: TcpEvent) {
        // consider self client or at least client believe
        // assume either LAST ACK or LAST FIN was allready send
        match event {
            TcpEvent::Timeout() => {
                // After waiting for errors ensure close the socket.
                ctrl.reset_connection_pars();
                inet_trace!("tcp::timewait '0x{:x} Closed", ctrl.fd);
                ctrl.state = TcpState::Closed;
            }
            TcpEvent::SysRecv() => unimplemented!(),
            TcpEvent::SysOpen(_) | TcpEvent::SysListen() => unimplemented!(),
            _ => {}, // ?
        }
    }

    fn process_state_close_wait(&mut self, ctrl: &mut TcpController, event: TcpEvent) {
        // consider self server
        // client will no longer receive data, but may still send
        match event {
            TcpEvent::Timeout() => {
                // ACK resend must be handled to get to ACK of FIN
                self.handle_data_timeout(ctrl)
            },
            TcpEvent::SysClose() => {
                // Once the application agrees to close 
                // send ACK of FIN
                inet_trace!("tcp::closewait '0x{:x}", ctrl.fd);

                // (0) Send own FIN
                let pkt = ctrl.create_packet(TcpPacketId::Fin, ctrl.sender_next_send_seq_no + 1, 0);
                self.tcp_send_packet(
                    ctrl, 
                    ctrl.ip_packet_for(pkt)
                );

          
                // (2) Wait for ACK
                // -> client will only send ACK as response to FIN
                ctrl.state = TcpState::LastAck;
            }
            _ => unimplemented!(),
        }
    }

    fn process_state_last_ack(&mut self, ctrl: &mut TcpController, event: TcpEvent) {
        // consider self server
        match event {
            TcpEvent::Ack(_) => {
                // (0) Each last ack will be only for FIN (else simultaneous close)
                ctrl.reset_connection_pars();
                ctrl.state = TcpState::Closed;
                inet_trace!("tcp::lastack '0x{:x} Closed", ctrl.fd);
            }
            _ => unimplemented!(),
        }
    }

    fn handle_data(&mut self, ctrl: &mut TcpController, src: IpAddr, dest:IpAddr, pkt: TcpPacket) {
        inet_trace!(
            "tcp::data '0x{:x} Data {{ ack: {}, max: {}, seq: {}, buf: {} }} with Packet {{ seq_no: {}, ack_no: {}, data: {} }}",
            ctrl.fd,
            ctrl.sender_last_ack_seq_no,
            ctrl.sender_max_send_seq_no,
            ctrl.sender_last_ack_seq_no,
            ctrl.sender_last_ack_seq_no,
            pkt.seq_no,
            pkt.ack_no,
            pkt.content.len()
        );

        // (A) Handle acknowledgement information
        if pkt.flags.ack {
            // let buf_full = self.send_queue == self.send_buffer.size();
            let buf_full = ctrl.sender_buffer.rem() == 0;

            ctrl.cancel_timer();
            if ctrl.sender_last_ack_seq_no < pkt.ack_no {
                let n = pkt.ack_no - ctrl.sender_last_ack_seq_no;
                ctrl.sender_buffer.free(n as usize);

                inet_trace!("tcp::data '0x{:x} freeing acked data: {} bytes", ctrl.fd, n);

                // freeBuffers
                ctrl.sender_last_ack_seq_no = pkt.ack_no;

                if ctrl.sender_last_ack_seq_no < ctrl.sender_next_send_seq_no {
                    ctrl.set_data_timer()
                } else {
                    // opti
                    ctrl.sender_next_send_seq_no = ctrl.sender_last_ack_seq_no;
                }

                if ctrl.congestion_ctrl {
                    if ctrl.congestion_window < ctrl.ssthresh {
                        ctrl.congestion_window += 1;
                        ctrl.congestion_avoid_counter = ctrl.congestion_window;
                    } else {
                        ctrl.congestion_avoid_counter = ctrl.congestion_avoid_counter.saturating_sub(1);
                        if ctrl.congestion_avoid_counter == 0 {
                            ctrl.congestion_window += 1;
                            ctrl.congestion_avoid_counter = ctrl.congestion_window;
                        }
                    }
                }

                if buf_full {
                    // SysStopInd
                }

                // Wakeup write interests
                ctrl.sender_write_interests.drain(..).for_each(|g| g.wake())
            }

            ctrl.sender_max_send_seq_no = pkt.ack_no + pkt.window as u32;  
            self.do_sending(ctrl);
        }

        // (B) Handle data part
        if !pkt.content.is_empty() {
            inet_trace!("tcp::data '0x{:x} {{DATA}} Got Packet {{ seq_no: {} }}", ctrl.fd, pkt.seq_no);
            ctrl.receiver_buffer.state();

            // (0) Capture the length of the readable slice before the incoming packet
            let prev = ctrl.receiver_buffer.state.valid_slice_len();

            // (1) Insert the packet into the receiver_buffer
            let n = ctrl.receiver_buffer.write_to(&pkt.content, pkt.seq_no);
            ctrl.receiver_last_recv_seq_no = pkt.seq_no + pkt.content.len() as u32;
            
            // TODO: 
            assert_eq!(n, pkt.content.len(), "Could not write received packet into buffer");

            // (2) If the readable slice has increased, new read interest may be fulfilled
            // so wake up corresponding guards. 
            let next = ctrl.receiver_buffer.state.valid_slice_len();
            if next > prev {
                ctrl.receiver_read_interests.drain(..).for_each(|g| g.wake());
            }

            // (3) Acknowledge the data that was send 
            self.send_ack(
                ctrl, 
                ctrl.receiver_last_recv_seq_no, 
                ctrl.recv_window()
            );

            ctrl.receiver_buffer.state();            
        }
    }

    fn do_sending(&mut self, ctrl: &mut TcpController) {

        // FIN may be send without window
        if ctrl.sender_max_send_seq_no == ctrl.sender_next_send_seq_no.saturating_sub(2) && true {
            inet_trace!("FIN without window");
            ctrl.sender_max_send_seq_no += 1;
        }

        let max_seq_no = if ctrl.congestion_ctrl {
            ctrl.sender_max_send_seq_no
                .min(ctrl.sender_last_ack_seq_no - 1 + ctrl.congestion_window)
        } else {
            ctrl.sender_max_send_seq_no
        };

        // Try sending data as long as:
        // a) Data is allowed to be send according to the minimal window
        // b) There is data to send in the sender_buffer
        
        while ctrl.sender_next_send_seq_no < max_seq_no
            && ctrl.sender_next_send_seq_no < ctrl.sender_next_send_buffer_seq_no
        {
            // send buffer set timeout
            // reschedule timer
            // get_data_packet
            // send

            ctrl.set_data_timer();

            // (0) Only send fragments within the remaining window and mtu limitiations
            let size = (ctrl.mtu as usize).min((max_seq_no - ctrl.sender_next_send_seq_no) as usize);
            let mut buf = vec![0u8; size];

            // (1) Peek the data from the sender_buffer (n = size)
            let n = ctrl.sender_buffer.peek_at(&mut buf,  ctrl.sender_next_send_seq_no);
            buf.truncate(n);
            inet_trace!("sending {} bytes (seq_no: {} max {})", n, ctrl.sender_next_send_seq_no, ctrl.sender_max_send_seq_no);

            // (2) Create a TCPData packet with the data embedded.
            let tcp = TcpPacket {
                src_port: ctrl.local_addr.port(),
                dest_port: ctrl.peer_addr.port(),
                seq_no: ctrl.sender_next_send_seq_no,
                ack_no: ctrl.receiver_last_recv_seq_no,
                flags: TcpFlags::new().ack(true),
                window: ctrl.recv_window(),
                urgent_ptr: 0,
                options: Vec::new(),
                content: buf,
            };
         
            // (3) Forward the packet to the socket output.
            self.tcp_send_packet(
                ctrl, 
                ctrl.ip_packet_for(tcp)
            );

            // (4) Increment the sequence number on success
            ctrl.sender_next_send_seq_no += n as u32;
        }
    }

    pub(self)  fn tcp_try_write(&mut self, fd: Fd, buf: &[u8]) -> Result<usize> {
        // log::debug!("::tcp_try_send");
        // (0) Get the socket
        let Some(mut ctrl) = self.tcp_manager.remove(&fd) else {
            return Err(Error::new(ErrorKind::InvalidInput, "invalid fd - socket dropped"))
        };

        // (1) If the socket is closing, send no more data
        if ctrl.state as u8 > TcpState::Established as u8 {
            self.tcp_manager.insert(fd, ctrl);
            return Ok(0)
        } 

        // (2) Write as much as possible to the send buffer
        let n = ctrl.sender_buffer.write(buf);
        ctrl.sender_next_send_buffer_seq_no += n as u32;
        if n == 0 {
            self.tcp_manager.insert(fd, ctrl);
            return Err(Error::new(ErrorKind::WouldBlock, "send buffer full - would block"))
        }
        
        self.do_sending(&mut ctrl);
        self.tcp_manager.insert(fd, ctrl);

        Ok(n)
    }


    pub(self)  fn tcp_try_read(&mut self, fd: Fd, buf: &mut [u8]) -> Result<usize> {
        // log::debug!("::tcp_try_recv");
        // (0) Get the socket
        let Some(mut ctrl) = self.tcp_manager.remove(&fd) else {
            return Err(Error::new(ErrorKind::InvalidInput, "invalid fd - socket dropped"))
        };

        // (1) Check for need for window updates.
        let was_full = ctrl.receiver_buffer.len() == ctrl.receiver_buffer.cap();

        // (2) This read operation will only read (and consume)
        // valid bytes according to the buffers state. The state
        // will be updated
        let n = ctrl.receiver_buffer.read(buf);
        if n == 0 {
            let nmd = ctrl.no_more_data_closed();
            self.tcp_manager.insert(fd, ctrl);
            if nmd {
                return Ok(n)
            } else {
                return Err(Error::new(ErrorKind::WouldBlock, "recv buffer empty - would block"))
            }     
        }

        if was_full {
            log::debug!("reinitiating send process since receive buffer is no longer full");
            let window = ctrl.recv_window();
            log::debug!("WIN: {}", window);
            let ack_no = ctrl.receiver_last_recv_seq_no ;
            self.send_ack(&mut ctrl, ack_no , window);
        }
        // ctrl.receiver_buffer.state();

        self.tcp_manager.insert(fd, ctrl);

        Ok(n)
    }

    pub(self) fn tcp_try_peek(&mut self, fd: Fd, buf: &mut [u8]) -> Result<usize> {
        // log::debug!("::tcp_try_peek");
        // (0) Get the socket
        let Some(mut ctrl) = self.tcp_manager.remove(&fd) else {
            return Err(Error::new(ErrorKind::InvalidInput, "invalid fd - socket dropped"))
        };

        // (1) This peek will only be into valid slice memory
        let n = ctrl.receiver_buffer.peek(&mut buf[..]);
        if n == 0 {
            self.tcp_manager.insert(fd, ctrl);
            return Err(Error::new(ErrorKind::WouldBlock, "recv buffer empty - would block"))
        }
        
        self.tcp_manager.insert(fd, ctrl);

        Ok(n)
    }

    fn handle_data_timeout(&mut self, ctrl: &mut TcpController) {
        inet_trace!("tcp::data '0x{:x} TIMEOUT", ctrl.fd);
        // TODO: Handle permit packets
        ctrl.sender_next_send_seq_no = ctrl.sender_last_ack_seq_no;
        ctrl.set_data_timer();

        self.do_sending(ctrl);
    }

    fn send_ack(&mut self, ctrl: &mut TcpController, next_expected: u32, win: u16) {
        assert!(next_expected > 0);
        let mut ack = ctrl.create_packet(
            TcpPacketId::Ack,
            ctrl.sender_next_send_seq_no,
            next_expected,
        );
        if win > 0 {
            ack.window = win;
        }
        
        self.tcp_send_packet(
            ctrl, 
            ctrl.ip_packet_for(ack)
        );
    }

    
}

impl TcpController {
    fn no_more_data_closed(&self) -> bool {
        matches!(self.state, TcpState::CloseWait | TcpState::LastAck | TcpState::Closed | TcpState::Closing | TcpState::TimeWait)
    }

    fn ip_packet_for(&self, tcp: TcpPacket) -> IpPacket {
        let content = tcp.into_buffer().unwrap();
        match self.local_addr {
            SocketAddr::V4(local) => {
                IpPacket::V4(Ipv4Packet {
                   
                    dscp: 0,
                    enc: 0,
                    identification: 0,
                    flags: Ipv4Flags { df: false, mf: false },
                    fragment_offset: 0,
                    ttl: 64,
                    proto: PROTO_TCP,
                
                    src: *local.ip(),
                    dest: if let IpAddr::V4(addr) = self.peer_addr.ip() { addr } else { unreachable!() },

                    content
                })
            }
            SocketAddr::V6(local) => {
                IpPacket::V6(Ipv6Packet {
                    traffic_class: 0,
                    flow_label: 0,
                    hop_limit: 64,
                    next_header: PROTO_TCP,
                    
                    
                    src: *local.ip(),
                    dest: if let IpAddr::V6(addr) = self.peer_addr.ip() { addr } else { unreachable!() },

                    content
                })
            }
        }

        
    }

    fn create_packet(&self, id: TcpPacketId, seq_no: u32, expected: u32) -> TcpPacket {
        let ack = expected != 0 || id == TcpPacketId::Ack;
        let syn = id == TcpPacketId::Syn;
        let fin = id == TcpPacketId::Fin;

        TcpPacket {
            src_port: self.local_addr.port(),
            dest_port: self.peer_addr.port(),
            seq_no,
            ack_no: expected,
            flags: TcpFlags::new()
                .ack(ack)
                .syn(syn)
                .fin(fin),
            window: 0,
            urgent_ptr:0,
            options: Vec::new(),
            content: Vec::new()
        }
    }

    fn syn_options(&self) -> Vec<TcpOption> {
        vec![
            TcpOption::MaximumSegmentSize(self.mtu),
            TcpOption::EndOfOptionsList()
        ]
    }

    fn apply_syn_options(&mut self, options: &[TcpOption]) {
        if let Some(mss) = options.iter().find_map(|v| if let TcpOption::MaximumSegmentSize(mss) = v { Some(mss) } else { None }) {
            self.mtu = self.mtu.min(*mss);
        }
    }

    fn set_data_timer(&mut self) {
        // inet_trace!("Setting data timer");
        self.timer += 1;
        schedule_in(
            Message::new().kind(KIND_IO_TIMEOUT).id(self.timer).content(self.fd).build(),
            self.timeout,
        );
    }

    fn cancel_timer(&mut self) {
        self.timer += 1;
    }

    fn send_buffer_len(&self) -> u32 {
        self.sender_next_send_buffer_seq_no - self.sender_next_send_seq_no
    }

    fn send_window(&self) -> u32 {
        self.sender_max_send_seq_no - (self.sender_next_send_seq_no - 1)
    }

    fn recv_window(&self) -> u16 {
        self.receiver_buffer.rem() as u16
        // (self.receiver_buffer.cap() - self.receiver_buffer.len()) as u16
    }

    fn set_timer(&mut self, expiration: Duration) {
        // inet_trace!("Setting normal timer");
        self.timer += 1;
        schedule_in(
            Message::new().kind(KIND_IO_TIMEOUT).id(self.timer).content(self.fd).build(),
            expiration,
        )
    }

    fn reset_connection_pars(&mut self) {
        self.state = TcpState::Closed;

        self.local_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
        self.peer_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);

        self.sender_last_ack_seq_no = 0;
        self.sender_next_send_seq_no = 0;
        self.sender_next_send_buffer_seq_no = 0;

        self.receiver_last_recv_seq_no = 0;
        self.sender_max_send_seq_no = 0;

        self.congestion_window = 1;
        self.congestion_avoid_counter = 0;
    }

    pub fn current_state_print(&self) {
        inet_trace!(
            "{:?}: Send {{ seq_no: {} buf_no: {}, max_no: {}, acked: {} }} and Recv {{ seq_no: {}, data: {} }}",
            self.state,
            self.sender_next_send_seq_no,
            self.sender_next_send_buffer_seq_no,
            self.sender_max_send_seq_no,
            self.sender_last_ack_seq_no,
            self.receiver_last_recv_seq_no,
            self.receiver_buffer.len()
        );
    }
}

// impl Drop for TcpController {
//     fn drop(&mut self) {
//         // panic!();
//         log::trace!("### DROPPING MANAGER FOR '0x{:x} ###", self.fd);
//     }
// }