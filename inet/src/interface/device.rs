use std::time::Duration;

use des::{
    net::module::current,
    prelude::{schedule_in, send, ChannelRef, GateRef, Message},
    time::SimTime,
};

use crate::routing::{RoutingInformation, RoutingPort};

use super::{InterfaceBusyState, MacAddress};

/// A descriptor for a network device that handles the
/// sending and receiving of MTUs.
#[derive(Debug, Clone)]
pub struct NetworkDevice {
    /// The physical address of the associated device
    pub addr: MacAddress,
    inner: NetworkDeviceInner,
}

pub(super) enum NetworkDeviceReadiness {
    Ready,
    Busy(SimTime),
}

impl From<NetworkDeviceReadiness> for InterfaceBusyState {
    fn from(value: NetworkDeviceReadiness) -> Self {
        match value {
            NetworkDeviceReadiness::Ready => InterfaceBusyState::Idle,
            NetworkDeviceReadiness::Busy(until) => InterfaceBusyState::Busy {
                until,
                interests: Vec::new(),
            },
        }
    }
}

#[derive(Debug, Clone)]
enum NetworkDeviceInner {
    /// The loopback device.
    LoopbackDevice,
    /// A network link described by two gates.
    EthernetDevice {
        output: GateRef,
        input: GateRef,
        channel: Option<ChannelRef>,
    },
}

impl NetworkDeviceInner {
    fn loopback() -> Self {
        Self::LoopbackDevice
    }

    fn ethernet(output: GateRef, input: GateRef) -> Self {
        // Limit iterations to prevent endless loops
        for conn in output
            .path_iter()
            .expect("cannot attach to transit gate")
            .take(16)
        {
            if let Some(channel) = conn.channel() {
                return Self::EthernetDevice {
                    output,
                    input,
                    channel: Some(channel),
                };
            }
        }

        // No channel attached to gate chain.
        tracing::warn!(
            "creating ethernet device with non-delayed link (staring at {})",
            output.path()
        );
        Self::EthernetDevice {
            output,
            input,
            channel: None,
        }
    }
}

impl NetworkDevice {
    pub fn is_loopback(&self) -> bool {
        matches!(self.inner, NetworkDeviceInner::LoopbackDevice)
    }

    pub fn input(&self) -> Option<GateRef> {
        match &self.inner {
            NetworkDeviceInner::EthernetDevice { input, .. } => Some(input.clone()),
            _ => None,
        }
    }

    /// Creates a local, loopback device.
    pub fn loopback() -> Self {
        Self {
            addr: MacAddress::NULL,
            inner: NetworkDeviceInner::loopback(),
        }
    }

    pub fn gate(name: &str, pos: usize) -> Option<Self> {
        let gate = current().gate(name, pos)?;
        Some(Self {
            addr: MacAddress::gen(),
            inner: NetworkDeviceInner::ethernet(gate.clone(), gate),
        })
    }

    /// Custom device
    pub fn custom(input: GateRef, output: GateRef) -> Self {
        Self {
            addr: MacAddress::gen(),
            inner: NetworkDeviceInner::ethernet(output, input),
        }
    }

    /// Creates the default ethernet device using the gates
    /// "in" and "out" as a duplex connection point.
    pub fn eth() -> Self {
        let mut rinfo = RoutingInformation::collect();
        match rinfo.ports.len() {
            0 => panic!("cannot create default ethernet device, module has no duplex port"),
            1 => {
                let port = rinfo.ports.swap_remove(0);
                Self {
                    addr: MacAddress::gen(),
                    inner: NetworkDeviceInner::ethernet(port.output, port.input),
                }
            }
            _ => {
                let default_port = rinfo
                    .ports
                    .into_iter()
                    .find(|p| p.input.name() == "port" && p.input.pos() == 0);

                if let Some(default_port) = default_port {
                    Self {
                        addr: MacAddress::gen(),
                        inner: NetworkDeviceInner::ethernet(
                            default_port.output,
                            default_port.input,
                        ),
                    }
                } else {
                    panic!("cannot create default ethernet device, module has mutiple valid ports, but not (in/out)")
                }
            }
        }
    }

    /// Creates a new device, by using the first routing port that
    /// statifies `f`.
    pub fn eth_select(f: impl Fn(&RoutingPort) -> bool) -> Self {
        let rinfo = RoutingInformation::collect();
        for r in rinfo.ports {
            let valid = f(&r);
            if valid {
                return Self {
                    addr: MacAddress::gen(),
                    inner: NetworkDeviceInner::ethernet(r.output, r.input),
                };
            }
        }

        unimplemented!("{:?}", RoutingInformation::collect())
    }

    pub fn bidirectional(name: impl AsRef<str>) -> Self {
        let name = name.as_ref();
        let rinfo = RoutingInformation::collect();
        for r in rinfo.ports {
            if r.name == name {
                return Self {
                    addr: MacAddress::gen(),
                    inner: NetworkDeviceInner::ethernet(r.output, r.input),
                };
            }
        }

        unimplemented!("{:?}", RoutingInformation::collect())
    }

    pub(super) fn ready(&self) -> NetworkDeviceReadiness {
        match &self.inner {
            NetworkDeviceInner::LoopbackDevice => NetworkDeviceReadiness::Ready,
            NetworkDeviceInner::EthernetDevice { channel, .. } => {
                let Some(chan) = channel else {
                    return NetworkDeviceReadiness::Ready;
                };

                if chan.is_busy() {
                    NetworkDeviceReadiness::Busy(
                        chan.transmission_finish_time() + Duration::from_nanos(1),
                    )
                } else {
                    NetworkDeviceReadiness::Ready
                }
            }
        }
    }

    pub(super) fn send(&self, mut msg: Message) -> NetworkDeviceReadiness {
        tracing::info!("send");
        msg.header_mut().src = self.addr.into();
        match &self.inner {
            NetworkDeviceInner::LoopbackDevice => {
                schedule_in(msg, Duration::ZERO);
                NetworkDeviceReadiness::Ready
            }
            NetworkDeviceInner::EthernetDevice {
                output, channel, ..
            } => {
                if let Some(channel) = channel {
                    assert!(!channel.is_busy(), "busy connector");
                    // Add the additionall delay to ensure the ChannelUnbusy event
                    // was at t1 < t2

                    // TODO: Is this delay still nessecary, since channels are now instantly
                    // busied with the call of send() thus channel updates are inorder before any
                    // link updates will arrive.
                    let tft = channel.calculate_busy(&msg) + Duration::from_nanos(1);
                    send(msg, output);

                    NetworkDeviceReadiness::Busy(SimTime::now() + tft)
                } else {
                    send(msg, output);
                    NetworkDeviceReadiness::Ready
                }
            }
        }
    }

    pub(super) fn last_gate_matches(&self, last_gate: &Option<GateRef>) -> bool {
        match &self.inner {
            NetworkDeviceInner::LoopbackDevice => last_gate.is_none(),
            NetworkDeviceInner::EthernetDevice { input, .. } => Some(input.clone()) == *last_gate,
        }
    }
}

impl From<RoutingPort> for NetworkDevice {
    fn from(port: RoutingPort) -> Self {
        NetworkDevice {
            addr: MacAddress::gen(),
            inner: NetworkDeviceInner::ethernet(port.output, port.input),
        }
    }
}
