use std::{collections::HashMap, net::IpAddr};

use des::prelude::{par_for, send};

use crate::ip::{Ipv4Packet, Ipv6Packet, KIND_IPV4, KIND_IPV6};

use super::{Router, RoutingInformation, RoutingPort};
pub struct ParBasedRoutingDeamon {
    info: RoutingInformation,
    fwd: HashMap<IpAddr, RoutingPort>,
}

impl ParBasedRoutingDeamon {
    pub fn new() -> Self {
        Self {
            info: RoutingInformation::emtpy(),
            fwd: HashMap::new(),
        }
    }
}

impl Router for ParBasedRoutingDeamon {
    fn initalize(&mut self, routing_info: RoutingInformation) {
        self.info = routing_info;

        for port in &self.info.ports {
            let Some(peer) = port.output.path_end() else {
                continue;
            };

            let Some(par) = par_for("addr", peer.owner().path().path()).as_optional() else {
                continue;
            };

            let addr = par.parse::<IpAddr>().unwrap();
            self.fwd.insert(addr, port.clone());
        }

        log::trace!("setup router with {} nodes", self.fwd.len())
    }

    fn accepts(&mut self, _: &des::prelude::Message) -> bool {
        true
    }

    fn route(&mut self, msg: des::prelude::Message) -> Result<(), des::prelude::Message> {
        match msg.header().kind {
            KIND_IPV4 => {
                let Some(ip) = msg.try_content::<Ipv4Packet>() else {
                    return Err(msg)
                };

                if let Some(target) = self.fwd.get(&IpAddr::V4(ip.dest)) {
                    // log::trace!("forwarding p{} to gate {}", ip.dest, target.output.path());
                    send(msg, &target.output);
                } else {
                    // log::trace!("forwarding p{} to uplink", ip.dest);
                    send(msg, "up")
                }

                Ok(())
            }
            KIND_IPV6 => {
                let Some(ip) = msg.try_content::<Ipv6Packet>() else {
                    return Err(msg)
                };

                if let Some(target) = self.fwd.get(&IpAddr::V6(ip.dest)) {
                    // log::trace!("forwarding p{} to gate {}", ip.dest, target.output.path());
                    send(msg, &target.output);
                } else {
                    // log::trace!("forwarding p{} to uplink", ip.dest);
                    send(msg, "up")
                }

                Ok(())
            }
            _ => Err(msg),
        }
    }
}
