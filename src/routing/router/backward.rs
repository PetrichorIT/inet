use crate::{ip::Ipv4Packet, FromBytestream};

use super::{super::RoutingPort, Router, RoutingInformation};
use des::prelude::*;
use std::collections::HashMap;

pub struct BackwardRoutingDeamon<R: Router> {
    info: RoutingInformation,
    knowledge: HashMap<Ipv4Addr, RoutingPort>,
    fallback: R,
}

impl<R: Router> BackwardRoutingDeamon<R> {
    pub fn new(fallback: R) -> Self {
        Self {
            info: RoutingInformation::emtpy(),
            knowledge: HashMap::new(),
            fallback,
        }
    }
}

impl<R: Router> Router for BackwardRoutingDeamon<R> {
    fn initalize(&mut self, routing_info: RoutingInformation) {
        self.fallback.initalize(routing_info.clone());
        self.info = routing_info;
    }

    fn accepts(&mut self, _: &Message) -> bool {
        true
    }

    fn route(&mut self, msg: Message) -> Result<(), Message> {
        // (0) Read packet
        let Some(vec) = msg.try_content::<Vec<u8>>() else {
            return Err(msg);
        };
        let pkt = Ipv4Packet::from_buffer(vec).unwrap();

        // (0) Try route with knowledge
        let msg_ip = pkt.dest;
        if let Some(record) = self.knowledge.get(&msg_ip) {
            send(msg, &record.output);
            return Ok(());
        }

        // (1) Record knowledge
        if let Some(last_gate) = &msg.header().last_gate {
            if let Some(port) = self.info.port_for(last_gate) {
                let src = pkt.src;
                if !self.knowledge.contains_key(&src) {
                    self.knowledge.insert(src, port);
                }
            }
        }

        // (2) Use fallback router
        self.fallback.route(msg)
    }
}
