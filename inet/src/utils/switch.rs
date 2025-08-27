use std::{collections::VecDeque, iter::repeat_with};

use crate::env::RoutingInformation;
use des::prelude::*;
use fxhash::{FxBuildHasher, FxHashMap};
use types::iface::MacAddress;

/// A marker to identify wakeup messages for the Switch.
///
/// Messages of this kind, will only ever be send using `schedule_at`,
/// so they should never leak into other modules.
pub const KIND_SWITCH_WAKEUP: MessageKind = 0x0600;

/// An module that acts as a no-config link layer switch.
///
/// This switch learns MAC addresses, by observing incoming packages.
/// By virtue of using ARP, all ajacent nodes will identifiy themselves using either
/// ARP responses or ARP requests (broadcast) before any data is send, so
/// the switch will have learned all nessecary data.
pub struct LinkLayerSwitch {
    info: RoutingInformation,
    // mac addr --> RoutingPort index
    mapping: FxHashMap<MacAddress, usize>,
    // index of RoutingPort in info --> queue
    queues: Vec<VecDeque<Message>>,
}

impl Default for LinkLayerSwitch {
    fn default() -> Self {
        Self {
            info: RoutingInformation::emtpy(),
            mapping: FxHashMap::with_hasher(FxBuildHasher::default()),
            queues: Vec::new(),
        }
    }
}

impl Module for LinkLayerSwitch {
    fn at_sim_start(&mut self, _: usize) {
        self.info = RoutingInformation::collect();
        self.queues = repeat_with(|| VecDeque::new())
            .take(self.info.ports.len())
            .collect();
    }

    fn handle_message(&mut self, msg: Message) {
        if msg.header().kind == KIND_SWITCH_WAKEUP {
            self.wakeup(*msg.body.content::<usize>());
            return;
        }

        let in_port = self.store_sender(&msg);
        let dst = MacAddress::from(msg.dst);

        if dst.is_broadcast() || dst.is_multicast() {
            for i in 0..self.info.ports.len() {
                if Some(i) == in_port {
                    continue;
                }

                // Broadcast ethernet packet.
                self.forward(msg.clone(), i);
            }
        } else {
            let Some(port) = self.mapping.get(&dst) else {
                tracing::error!(
                    "could not find addr {} in local mapping: either not existent or not active",
                    dst
                );
                return;
            };

            self.forward(msg, *port)
        }
    }

    fn at_sim_end(&mut self) -> Result<(), RuntimeError> {
        assert!(self.queues.iter().all(|q| q.is_empty()));
        Ok(())
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
        if src.is_unspecified() || src.is_broadcast() || src.is_multicast() {
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
                    let tft = ch.transmission_finish_time().unwrap();
                    schedule_at(
                        Message::default()
                            .with_kind(KIND_SWITCH_WAKEUP)
                            .with_content(i),
                        tft,
                    );
                }
            } else {
                // (4) Send the message directly (onto the original gate though)
                if let Err(e) = send(msg, self.info.ports[i].output.clone()) {
                    tracing::error!(
                        "switch cannot send message onto channel for some unknown reason"
                    );
                    drop(e);
                }
            }
        } else {
            // (5) No channel in the entire gate chain
            send(msg, self.info.ports[i].output.clone()).expect("no channel, thus cannot fail");
        }
    }

    fn wakeup(&mut self, i: usize) {
        let Some(msg) = self.queues[i].pop_front() else {
            unreachable!()
        };

        let gate = self.info.ports[i].output.clone();
        if let Err(e) = send(msg, &gate) {
            tracing::error!("switch cannot send message onto channel after wakeup: ERRIMPL");
            drop(e);
        }

        // reschedule
        if !self.queues[i].is_empty() {
            // we can assume that a channel exists, since wakeup only occure on bufferd ports
            let mut gate = gate;
            while let Some(next_gate) = gate.next_gate() {
                if let Some(ch) = gate.channel() {
                    let tft = ch.transmission_finish_time().unwrap();
                    schedule_at(
                        Message::default()
                            .with_kind(KIND_SWITCH_WAKEUP)
                            .with_content(i),
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
