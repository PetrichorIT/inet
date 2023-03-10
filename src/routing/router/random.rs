use super::{Router, RoutingInformation};
use des::prelude::*;

pub struct RandomRoutingDeamon {
    info: RoutingInformation,
    counter: usize,
}

impl RandomRoutingDeamon {
    pub fn new() -> Self {
        Self {
            info: RoutingInformation::emtpy(),
            counter: 0,
        }
    }
}

impl Router for RandomRoutingDeamon {
    fn initalize(&mut self, routing_info: RoutingInformation) {
        self.info = routing_info;
    }

    fn accepts(&mut self, _: &Message) -> bool {
        true
    }

    fn route(&mut self, msg: Message) -> Result<(), Message> {
        let Some(last_gate) = &msg.header().last_gate else {
            return Err(msg)
        };
        let Some(port) = self.info.port_for(last_gate) else {
            return Err(msg)
        };

        if self.info.ports.len() == 1 {
            send(msg, port.output);
            self.counter += 1;
            return Ok(());
        }

        let mut choose_port = random::<usize>() % self.info.ports.len();
        if self.info.ports[choose_port] == port {
            choose_port = (choose_port + 1) % self.info.ports.len();
        }

        send(msg, &self.info.ports[choose_port].output);
        self.counter += 1;

        Ok(())
    }
}
