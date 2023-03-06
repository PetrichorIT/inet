use std::time::Duration;

use des::{
    prelude::{gate, schedule_in, send, GateRef, Message},
    time::SimTime,
};

use super::{InterfaceBusyState, MacAddress};

/// A descriptor for a network device that handles the
/// sending and receiving of MTUs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkDevice {
    pub addr: MacAddress,
    inner: NetworkDeviceInner,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum NetworkDeviceInner {
    /// The loopback device.
    LoopbackDevice,
    /// A network link described by two gates.
    EthernetDevice { output: GateRef, input: GateRef },
}

impl NetworkDevice {
    pub fn loopback() -> Self {
        Self {
            addr: MacAddress::NULL,
            inner: NetworkDeviceInner::LoopbackDevice,
        }
    }

    pub fn eth_default() -> Self {
        Self {
            addr: MacAddress::gen(),
            inner: NetworkDeviceInner::EthernetDevice {
                output: gate("out", 0)
                    .expect("Failed to create default ethernet device with gate: out"),
                input: gate("in", 0)
                    .expect("Failed to create default ethernet device with gate: in"),
            },
        }
    }

    pub(super) fn send(&self, mut msg: Message) -> InterfaceBusyState {
        msg.header_mut().src = self.addr.into();
        match &self.inner {
            NetworkDeviceInner::LoopbackDevice => {
                schedule_in(msg, Duration::ZERO);
                InterfaceBusyState::Idle
            }
            NetworkDeviceInner::EthernetDevice { output, .. } => {
                if let Some(channel) = output.channel() {
                    // Add the additionall delay to ensure the ChannelUnbusy event
                    // was at t1 < t2
                    let tft = channel.calculate_busy(&msg) + Duration::from_nanos(1);
                    send(msg, output);

                    InterfaceBusyState::Busy {
                        until: SimTime::now() + tft,
                        interests: Vec::new(),
                    }
                } else {
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
