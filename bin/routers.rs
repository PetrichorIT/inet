use std::net::IpAddr;

use des::prelude::*;
use inet::{
    ip::{IpMask, Ipv6Packet, Ipv4Packet, Ipv4Mask, KIND_IPV4, KIND_IPV6},
    routing::{ParBasedRoutingDeamon, RoutingInformation, RoutingPlugin, RoutingPort},
};

#[NdlModule("bin")]
pub struct LANRouter {}

impl Module for LANRouter {
    fn new() -> Self {
        Self {}
    }

    fn at_sim_start(&mut self, _stage: usize) {
        add_plugin(RoutingPlugin(ParBasedRoutingDeamon::new()), 1);
    }
}

#[NdlModule("bin")]
pub struct WANRouter {
    info: RoutingInformation,
    fwd: Vec<(IpMask, RoutingPort)>,
    backup: Option<RoutingPort>,
}

impl Module for WANRouter {
    fn new() -> Self {
        Self {
            info: RoutingInformation::emtpy(),
            fwd: Vec::new(),
            backup: None,
        }
    }

    fn at_sim_start(&mut self, stage: usize) {
        if stage == 1 {
            self.info = RoutingInformation::collect();

            for port in &self.info.ports {
                let Some(end) = port.output.path_end() else {
                    continue;
                };

                match end.name() {
                    "down" => {                      
                        let Some(addr) = par_for("addr", end.owner().path().parent_path()).as_optional() else {
                            continue;
                        };

                        let addr = addr.parse::<IpAddr>().unwrap();
                        let IpAddr::V4(addr) = addr else {
                            continue;
                        };

                        let mask = IpMask::V4(Ipv4Mask::new(addr, Ipv4Addr::new(255,255,255,0)));
                        self.fwd.push((mask, port.clone()))
                    }
                    "in" => {
                        self.backup = Some(port.clone());
                    }
                    _ => {}
                }
            }

            log::trace!(
                "Set forwarding port {} and {} network rules",
                self.backup
                    .as_ref()
                    .unwrap()
                    .output
                    .path_end()
                    .unwrap()
                    .owner()
                    .path(),
                self.fwd.len()
            );
        }
    }

    fn num_sim_start_stages(&self) -> usize {
        2
    }

    fn handle_message(&mut self, msg: Message) {
        match msg.header().kind {
            KIND_IPV4 => {
                let Some(ip) = msg.try_content::<Ipv4Packet>() else {
                    return 
                };

                if let Some(port) = self.get_fwd(IpAddr::V4(ip.dest)) {
                    // let Some(port) = self.info.port_by_name(target) else {
                    //     return
                    // };

                    
                    // log::trace!("forwarding p{} to network {}", ip.dest, port.output.path_end().unwrap().owner().path().parent_path());
                    send(msg, port.output);
                } else {
                    // log::trace!("forwarding p{} at cycle", ip.dest);
                    send(msg, &self.backup.as_ref().unwrap().output);
                }
            }
            KIND_IPV6 => {
                let Some(ip) = msg.try_content::<Ipv6Packet>() else {
                    return 
                };

                if let Some(port) = self.get_fwd(IpAddr::V6(ip.dest)) {
                    // let Some(port) = self.info.port_by_name(target) else {
                    //     return
                    // };

                    // log::trace!("forwarding p{} to network {}", ip.dest, port.output.path_end().unwrap().owner().path().parent_path());
                    send(msg, port.output);
                } else {
                    // log::trace!("forwarding p{} at cycle", ip.dest);
                    send(msg, &self.backup.as_ref().unwrap().output);
                }
            }
            _ => {},
        }
    }
}

impl WANRouter {
    fn get_fwd(&self, ip: IpAddr) -> Option<RoutingPort> {
        for (mask, port) in self.fwd.iter() {
            if mask.matches(ip) {
                return Some(port.clone());
            }
        }
        None
    }
}