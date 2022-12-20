use super::{Router, RoutingInformation, RoutingPort};
use des::prelude::*;
use std::{collections::HashMap, net::IpAddr};

pub struct BackwardRoutingDeamon<R: Router> {
    info: RoutingInformation,
    knowledge: HashMap<IpAddr, RoutingPort>,
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

    fn accepts(&mut self, msg: &Message) -> bool {
        let msg_ip = msg.header().dest_addr.ip();
        self.knowledge.get(&msg_ip).is_some() || self.fallback.accepts(msg)
    }

    fn route(&mut self, msg: Message) -> Result<(), Message> {
        // (0) Try route with knowledge
        let msg_ip = msg.header().dest_addr.ip();
        if let Some(record) = self.knowledge.get(&msg_ip) {
            send(msg, &record.output);
            return Ok(());
        }

        // (1) Record knowledge
        if let Some(last_gate) = &msg.header().last_gate {
            if let Some(port) = self.info.port_for(last_gate) {
                let src = msg.header().src_addr.ip();
                self.knowledge.insert(src, port);
            }
        }

        // (2) Use fallback router
        self.fallback.route(msg)
    }
}
