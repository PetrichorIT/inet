use std::time::Duration;

use des::prelude::{gate, schedule_in, send, GateRef, Message};

/// A descriptor for a network device that handles the
/// sending and receiving of MTUs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkDevice {
    /// The loopback device.
    LoopbackDevice,
    /// A network link described by two gates.
    EthernetDevice { output: GateRef, input: GateRef },
}

impl NetworkDevice {
    pub fn loopback() -> Self {
        Self::LoopbackDevice
    }

    pub fn eth_default() -> Self {
        Self::EthernetDevice {
            output: gate("out", 0)
                .expect("Failed to create default ethernet device with gate: out"),
            input: gate("in", 0).expect("Failed to create default ethernet device with gate: in"),
        }
    }

    pub(super) fn send_mtu(&self, mtu: Message) {
        match self {
            Self::LoopbackDevice => schedule_in(mtu, Duration::ZERO),
            Self::EthernetDevice { output, .. } => send(mtu, output),
        }
    }

    pub(super) fn last_gate_matches(&self, last_gate: &Option<GateRef>) -> bool {
        match self {
            Self::LoopbackDevice => last_gate.is_none(),
            Self::EthernetDevice { input, .. } => Some(input.clone()) == *last_gate,
        }
    }
}
