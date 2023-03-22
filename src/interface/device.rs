use std::time::Duration;

use des::{
    prelude::{schedule_in, send, ChannelRef, GateRef, Message},
    time::SimTime,
};

use crate::routing::{RoutingInformation, RoutingPort};

use super::{InterfaceBusyState, MacAddress};

/// A descriptor for a network device that handles the
/// sending and receiving of MTUs.
#[derive(Debug, Clone)]
pub struct NetworkDevice {
    pub addr: MacAddress,
    inner: NetworkDeviceInner,
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
        let mut gate = output.clone();
        while let Some(next_gate) = gate.next_gate() {
            // (0) check whether the current link contains a channel.
            if let Some(channel) = gate.channel() {
                return Self::EthernetDevice {
                    output,
                    input,
                    channel: Some(channel),
                };
            }

            gate = next_gate
        }

        // No channel attached to gate chain.
        log::warn!(target: "inet/iface", "creating ethernet device with non-delayed link (staring at {})", output.path());
        Self::EthernetDevice {
            output,
            input,
            channel: None,
        }
    }
}

impl NetworkDevice {
    pub fn loopback() -> Self {
        Self {
            addr: MacAddress::NULL,
            inner: NetworkDeviceInner::loopback(),
        }
    }

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
                let inout = rinfo
                    .ports
                    .into_iter()
                    .find(|p| p.input.name() == "in" && p.output.name() == "out");

                if let Some(inout) = inout {
                    Self {
                        addr: MacAddress::gen(),
                        inner: NetworkDeviceInner::ethernet(inout.output, inout.input),
                    }
                } else {
                    panic!("cannot create default ethernet device, module has mutiple valid ports, but not (in/out)")
                }
            }
        }
    }

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

    pub(super) fn send(&self, mut msg: Message) -> InterfaceBusyState {
        msg.header_mut().src = self.addr.into();
        match &self.inner {
            NetworkDeviceInner::LoopbackDevice => {
                schedule_in(msg, Duration::ZERO);
                InterfaceBusyState::Idle
            }
            NetworkDeviceInner::EthernetDevice {
                output, channel, ..
            } => {
                if let Some(channel) = channel {
                    // Add the additionall delay to ensure the ChannelUnbusy event
                    // was at t1 < t2

                    // TODO: Is this delay still nessecary, since channels are now instantly
                    // busied with the call of send() thus channel updates are inorder before any
                    // link updates will arrive.
                    let tft = channel.calculate_busy(&msg) + Duration::from_nanos(1);
                    send(msg, output);

                    InterfaceBusyState::Busy {
                        until: SimTime::now() + tft,
                        interests: Vec::new(),
                    }
                } else {
                    send(msg, output);
                    InterfaceBusyState::Idle
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

    pub(super) fn is_busy(&self) -> bool {
        match &self.inner {
            NetworkDeviceInner::LoopbackDevice => false,
            NetworkDeviceInner::EthernetDevice { output, .. } => {
                output.channel().map(|v| v.is_busy()).unwrap_or(false)
            }
        }
    }
}
