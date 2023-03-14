use des::prelude::*;

pub mod router;

mod tablev6;
pub use self::tablev6::*;

mod tablev4;
pub use self::tablev4::*;

mod api;
pub use self::api::*;

use crate::IOPlugin;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutingInformation {
    pub ports: Vec<RoutingPort>,
    pub node_ip: IpAddr,
}

impl RoutingInformation {
    pub fn emtpy() -> Self {
        Self {
            ports: Vec::new(),
            node_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        }
    }

    pub fn collect() -> Self {
        Self {
            ports: RoutingPort::collect(),
            node_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        }
    }

    pub fn port_for(&self, gate: &GateRef) -> Option<RoutingPort> {
        self.ports.iter().find(|p| p.input == *gate).cloned()
    }

    pub fn port_index_for(&self, gate: &GateRef) -> Option<usize> {
        self.ports
            .iter()
            .enumerate()
            .find(|(_, p)| p.input == *gate)
            .map(|(i, _)| i)
    }

    pub fn port_by_name(&self, s: &str) -> Option<RoutingPort> {
        self.ports.iter().find(|p| p.name == s).cloned()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutingPort {
    pub name: String,
    pub input: GateRef,
    pub output: GateRef,
    pub peer: Option<RoutingPeer>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutingPeer {
    pub addr: IpAddr,
}

impl RoutingPort {
    pub fn new(input: GateRef, output: GateRef, peer: Option<RoutingPeer>) -> Self {
        let iname = input.name();
        let oname = output.name();

        Self {
            name: merge_str(iname, oname),
            input,
            output,
            peer,
        }
    }

    pub fn collect() -> Vec<RoutingPort> {
        let mut gates = gates();
        let mut ports = Vec::new();
        while let Some(gate) = gates.pop() {
            let typ = inferred_service_type(&gate);
            match typ {
                GateServiceType::Input => {
                    let id = gate
                        .path_start()
                        .map(|v| v.owner().id())
                        .unwrap_or(ModuleId::NULL);

                    let other = gates.iter().find(|v| {
                        v.path_end()
                            .map(|v| v.owner().id())
                            .unwrap_or(ModuleId::NULL)
                            == id
                            && inferred_service_type(*v) == GateServiceType::Output
                    });

                    let Some(other) = other else {
                        continue;
                    };

                    let peer = other
                        .path_end()
                        .unwrap()
                        .owner()
                        .get_plugin_state::<IOPlugin, Option<IpAddr>>()
                        .flatten()
                        .map(|addr| RoutingPeer { addr });

                    ports.push(RoutingPort::new(gate, other.clone(), peer));
                }
                GateServiceType::Output => {
                    let id = gate
                        .path_end()
                        .map(|v| v.owner().id())
                        .unwrap_or(ModuleId::NULL);

                    let other = gates.iter().find(|v| {
                        v.path_start()
                            .map(|v| v.owner().id())
                            .unwrap_or(ModuleId::NULL)
                            == id
                            && inferred_service_type(*v) == GateServiceType::Input
                    });

                    let Some(other) = other else {
                        continue;
                    };

                    let peer = gate
                        .path_end()
                        .map(|e| {
                            e.owner()
                                .get_plugin_state::<IOPlugin, Option<IpAddr>>()
                                .flatten()
                                .map(|addr| RoutingPeer { addr })
                        })
                        .flatten();

                    ports.push(RoutingPort::new(other.clone(), gate, peer));
                }
                GateServiceType::Undefined => {}
            };
        }

        // for port in &ports {
        //     println!(
        //         "Port {} input {} output {}",
        //         port.name,
        //         port.input.path(),
        //         port.output.path()
        //     );
        // }

        ports
    }
}

pub(crate) enum IpGateway {
    Local,
    Broadcast,
    Gateway(IpAddr),
}

impl From<Ipv4Gateway> for IpGateway {
    fn from(value: Ipv4Gateway) -> Self {
        match value {
            Ipv4Gateway::Local => IpGateway::Local,
            Ipv4Gateway::Broadcast => IpGateway::Broadcast,
            Ipv4Gateway::Gateway(ip) => IpGateway::Gateway(ip.into()),
        }
    }
}

impl From<Ipv6Gateway> for IpGateway {
    fn from(value: Ipv6Gateway) -> Self {
        match value {
            Ipv6Gateway::Local => IpGateway::Local,
            Ipv6Gateway::Broadcast => IpGateway::Broadcast,
            Ipv6Gateway::Gateway(ip) => IpGateway::Gateway(ip.into()),
        }
    }
}

fn inferred_service_type(gate: &GateRef) -> GateServiceType {
    match gate.service_type() {
        GateServiceType::Undefined => {
            if gate.next_gate().is_none() && gate.previous_gate().is_some() {
                return GateServiceType::Input;
            }
            if gate.previous_gate().is_none() && gate.next_gate().is_some() {
                return GateServiceType::Output;
            }
            GateServiceType::Undefined
        }
        v => v,
    }
}

fn merge_str(lhs: &str, rhs: &str) -> String {
    let mut s = String::with_capacity(lhs.len().max(rhs.len()));
    let mut lhs = lhs.chars();
    let mut rhs = rhs.chars();
    while let (Some(l), Some(r)) = (lhs.next(), rhs.next()) {
        if l == r {
            s.push(l);
        }
    }
    s
}
