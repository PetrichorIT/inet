use des::prelude::*;

mod random;
pub use random::RandomRoutingDeamon;

mod backward;
pub use backward::BackwardRoutingDeamon;

mod stacked;
pub use stacked::StackedRoutingDeamon;

mod par_based;
pub use par_based::ParBasedRoutingDeamon;

mod plugin;
pub use plugin::RoutingPlugin;

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

    pub fn port_by_name(&self, s: &str) -> Option<RoutingPort> {
        self.ports.iter().find(|p| p.name == s).cloned()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutingPort {
    pub name: String,
    pub input: GateRef,
    pub output: GateRef,
}

impl RoutingPort {
    pub fn new(input: GateRef, output: GateRef) -> Self {
        let iname = input.name();
        let oname = output.name();

        Self {
            name: merge_str(iname, oname),
            input,
            output,
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
                    // println!("{}")
                    ports.push(RoutingPort::new(gate, other.clone()));
                }
                GateServiceType::Output => {
                    let id = gate
                        .path_end()
                        .map(|v| v.owner().id())
                        .unwrap_or(ModuleId::NULL);
                    // println!("{:?}", gate.previous_gate());
                    // println!("{}", gate.path_end().unwrap().path());
                    // println!("Searching gate for {} with id {}", gate.path(), id);
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
                    ports.push(RoutingPort::new(other.clone(), gate));
                }
                GateServiceType::Undefined => log::warn!("Found undefined gate service typ"),
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

pub trait Router {
    fn initalize(&mut self, routing_info: RoutingInformation);
    fn accepts(&mut self, msg: &Message) -> bool;
    fn route(&mut self, msg: Message) -> Result<(), Message>;
}
