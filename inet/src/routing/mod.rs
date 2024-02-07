//! Routing utility and networking layer processing.
use crate::ctx::IOMeta;
use des::net::gate::GateKind;
use des::prelude::*;

mod tablev6;
pub use self::tablev6::Ipv6RouterConfig;
pub(crate) use self::tablev6::*;

mod api;
pub use self::api::*;

mod fwdv4;
pub use self::fwdv4::*;

/// A collection of information readable
/// from the topology alone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutingInformation {
    /// A set of ports that can be used as duplex connections.
    pub ports: Vec<RoutingPort>,
    /// The IP address of the current node.
    pub node_ip: IpAddr,
}

impl RoutingInformation {
    /// A const default for no routing info.
    pub const fn emtpy() -> Self {
        Self {
            ports: Vec::new(),
            node_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        }
    }

    /// The routing information for the current module, collected from the env.
    pub fn collect() -> Self {
        Self {
            ports: RoutingPort::collect(),
            node_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        }
    }

    /// Maps a given gate to the associated routing port, if existent.
    pub fn port_for(&self, gate: &GateRef) -> Option<RoutingPort> {
        self.ports.iter().find(|p| p.input == *gate).cloned()
    }

    /// Maps a given gate to the associated routing port index, if existent.
    pub fn port_index_for(&self, gate: &GateRef) -> Option<usize> {
        self.ports
            .iter()
            .enumerate()
            .find(|(_, p)| p.input == *gate)
            .map(|(i, _)| i)
    }

    /// Maps the port names to a routing port, if existent.
    pub fn port_by_name(&self, s: &str) -> Option<RoutingPort> {
        self.ports.iter().find(|p| p.name == s).cloned()
    }
}

/// A physical send, receive pair, that can be used as a duplex connections.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutingPort {
    /// The name of the port, if derived, the common prefix of both input and output.s
    pub name: String,
    /// The receiving gate.
    pub input: GateRef,
    /// The sending gate.
    pub output: GateRef,
    /// Peering information that can be aquired from the topology.
    pub peer: Option<RoutingPeer>,
}

/// Information about the peer of a connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutingPeer {
    /// The peers IP address.
    pub addr: IpAddr,
}

impl RoutingPort {
    /// Creates a new routing port manually.
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

    /// Reads all possible routing ports from the env.
    pub fn collect() -> Vec<RoutingPort> {
        let gates = current().gates();
        let mut ports = Vec::new();

        // (0) Preprocessing

        for gate in gates {
            match gate.kind() {
                GateKind::Endpoint => ports.push(RoutingPort {
                    name: gate.name().to_string(),
                    input: gate.clone(),
                    output: gate.clone(),
                    peer: gate
                        .path_end()
                        .map(|end| {
                            end.owner()
                                .meta::<IOMeta>()
                                .map(|io| io.ip)
                                .flatten()
                                .map(|addr| RoutingPeer { addr })
                        })
                        .flatten(),
                }),
                _ => {}
            }
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
            _ => todo!(),
        }
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
