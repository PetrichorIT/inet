use std::{collections::VecDeque, iter::repeat_with};

use crate::{arp::ArpPacket, interface::MacAddress, routing::RoutingInformation};
use des::prelude::*;
use fxhash::{FxBuildHasher, FxHashMap};
use inet_types::ip::{Ipv4Packet, Ipv6Packet};

pub const KIND_SWITCH_WAKEUP: MessageKind = 0x0600;

pub struct LinkLayerSwitch {
    info: RoutingInformation,
    // mac addr --> RoutingPort index
    mapping: FxHashMap<MacAddress, usize>,
    // index of RoutingPort in info --> queue
    queues: Vec<VecDeque<Message>>,
}

impl Module for LinkLayerSwitch {
    fn new() -> Self {
        Self {
            info: RoutingInformation::emtpy(),
            mapping: FxHashMap::with_hasher(FxBuildHasher::default()),
            queues: Vec::new(),
        }
    }

    fn at_sim_start(&mut self, _: usize) {
        self.info = RoutingInformation::collect();
        self.queues = repeat_with(|| VecDeque::new())
            .take(self.info.ports.len())
            .collect();
    }

    fn handle_message(&mut self, msg: Message) {
        if msg.header().kind == KIND_SWITCH_WAKEUP {
            self.wakeup(*msg.content::<usize>());
            return;
        }

        let in_port = self.store_sender(&msg);
        let dest = MacAddress::from(msg.header().dest);

        if dest.is_broadcast() {
            for i in 0..self.info.ports.len() {
                if Some(i) == in_port {
                    continue;
                }

                // Broadcast ethernet packet.
                if msg.can_cast::<ArpPacket>() {
                    self.forward(msg.dup::<ArpPacket>(), i);
                    continue;
                }

                if msg.can_cast::<Ipv4Packet>() {
                    self.forward(msg.dup::<Ipv4Packet>(), i);
                    continue;
                }

                if msg.can_cast::<Ipv6Packet>() {
                    self.forward(msg.dup::<Ipv6Packet>(), i);
                    continue;
                }

                log::error!(target: "inet/switch", "could not duplicate packet {}: unexpected content", msg.str())
            }
        } else {
            let Some(port) = self.mapping.get(&dest) else {
                log::error!(target: "inet/switch", "could not find addr {} in local mapping: either not existent or not active", dest);
                return
            };

            self.forward(msg, *port)
        }
    }

    fn at_sim_end(&mut self) {
        assert!(self.queues.iter().all(|q| q.is_empty()))
    }
}

impl LinkLayerSwitch {
    fn store_sender(&mut self, msg: &Message) -> Option<usize> {
        let Some(ref last_gate) = msg.header().last_gate else {
            return None;
        };
        let Some(i) = self.info.port_index_for(last_gate) else {
            return None;
        };

        let src = MacAddress::from(msg.header().src);
        if src.is_unspecified() || src.is_broadcast() {
            return Some(i);
        }
        self.mapping.insert(src, i);
        Some(i)
    }

    fn forward(&mut self, msg: Message, i: usize) {
        // (0) Get routing port output gate
        let mut gate = self.info.ports[i].output.clone();

        // (1) Iterate until a channel is reached.
        while let Some(next_gate) = gate.next_gate() {
            if gate.channel().is_some() {
                break;
            } else {
                gate = next_gate;
            }
        }

        if let Some(ch) = gate.channel() {
            // (2) channel found.
            if ch.is_busy() {
                // (3) Buffer the current message
                self.queues[i].push_back(msg);
                if self.queues[i].len() == 1 {
                    // First message that was enqueued, no timeout in flight
                    let tft = ch.transmission_finish_time();
                    schedule_at(
                        Message::new().kind(KIND_SWITCH_WAKEUP).content(i).build(),
                        tft,
                    );
                }
            } else {
                // (4) Send the message directly (onto the original gate though)
                send(msg, self.info.ports[i].output.clone())
            }
        } else {
            // (5) No channel in the entire gate chain
            send(msg, self.info.ports[i].output.clone())
        }
    }

    fn wakeup(&mut self, i: usize) {
        let Some(msg) = self.queues[i].pop_front() else {
            unreachable!()
        };

        let gate = self.info.ports[i].output.clone();
        send(msg, &gate);
        if !self.queues[i].is_empty() {
            // we can assume that a channel exists, since wakeup only occure on bufferd ports
            let mut gate = gate;
            while let Some(next_gate) = gate.next_gate() {
                if let Some(ch) = gate.channel() {
                    let tft = ch.transmission_finish_time();
                    schedule_at(
                        Message::new().kind(KIND_SWITCH_WAKEUP).content(i).build(),
                        tft,
                    );
                    break;
                } else {
                    gate = next_gate;
                }
            }
        }
    }
}

// impl LinkLayerSwitch {
//     fn send_out(&mut self, msg: Message, pos: usize) {
//         let gate = gate("out", pos).unwrap();
//         if let Some(ch) = gate.channel() {
//             if ch.is_busy() {
//                 // channel busy semantics must change
//                 self.queues.entry(pos).or_insert(Vec::new()).push(msg);
//                 let tft = ch.transmission_finish_time();
//                 if self.queues.get(&pos).unwrap().len() == 1 {
//                     schedule_at(Message::new().kind(11).content(pos).build(), tft)
//                 }
//             } else {
//                 send(msg, gate)
//             }
//         } else {
//             send(msg, gate)
//         }
//     }

//     fn link_update(&mut self, pos: usize) {
//         let queue = self.queues.get_mut(&pos).unwrap();
//         let msg = queue.remove(0);

//         if !queue.is_empty() {
//             let gate = gate("out", pos).unwrap();
//             let ch = gate.channel().unwrap();
//             let delay = ch.calculate_busy(&msg);

//             schedule_in(Message::new().kind(11).content(pos).build(), delay)
//         }

//         send(msg, ("out", pos));
//     }
// }
