use des::prelude::*;

pub mod rip;
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
        let gates = gates();
        let mut ports = Vec::new();

        // (0) Preprocessing
        let mut inputs = Vec::with_capacity(gates.len() / 2);
        let mut outputs = Vec::with_capacity(gates.len() / 2);

        for gate in gates {
            match gate.service_type() {
                GateServiceType::Input => inputs.push(gate),
                GateServiceType::Output => outputs.push(gate),
                _ => {}
            }
        }

        // (1) Presorting for better performance
        // TODO

        // (2) Search for valid paths

        for output in outputs {
            let Some((peer, addr)) = output.path_end().map(|e| (e.owner().id(), e.owner().get_plugin_state::<IOPlugin, Option<IpAddr>>().flatten().map(|addr| RoutingPeer { addr }))) else {
                continue;
            };

            let pair = inputs.iter().find(|g| {
                let Some(pair_peer) = g.path_start().map(|s| s.owner().id()) else {
                    return false;
                };
                pair_peer == peer
            });

            let Some(pair) = pair else { continue };
            ports.push(RoutingPort::new(pair.clone(), output, addr));
        }

        ports
    }
}

unsafe impl Send for RoutingPort {}
unsafe impl Sync for RoutingPort {}

#[derive(Debug)]
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

#[allow(unused)]
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
