//! Routing utility and networking layer processing.
use des::net::gate::GateKind;
use des::prelude::*;

pub mod fs;

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
    #[allow(clippy::single_match)]
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
                    peer: gate.path_end().and_then(|end| {
                        end.owner()
                            .prop::<Option<IpAddr>>("inet.meta")
                            .ok()
                            .and_then(|io| io.get())
                            .and_then(|addr| addr.map(|addr| RoutingPeer { addr }))
                    }),
                }),
                _ => {}
            }
        }

        ports
    }
}

unsafe impl Send for RoutingPort {}
unsafe impl Sync for RoutingPort {}

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
