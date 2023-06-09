//! An interfaces for capturing packets, akin to libpcap.

use crate::interface::Interface;
use des::prelude::{module_id, Message, ModuleId};
use std::cell::RefCell;
use std::io::Result;

macro_rules! try_warn {
    ($e:expr) => {
        match $e {
            Ok(()) => {}
            Err(e) => {
                tracing::warn!("pcap failed with subscriber: {e}")
            }
        }
    };
}

thread_local! {
    static LIBPCAP: RefCell<Pcap> = const { RefCell::new(Pcap::new()) };
}

struct Pcap {
    mapping: Vec<(ModuleId, Box<dyn PcapSubscriber>)>,
}

/// A mounting point for a module-local subscriber to
/// events from libpcap abstractions.
pub trait PcapSubscriber {
    /// Indicates whether to forward packets from a specific capture point.
    ///
    /// If not explicitly specified, no packets will be
    /// forwarded to the capture handle.s
    fn enable_capture(&self, point: PcapCapturePoint) -> bool;

    /// Captures a packet with associated metadata.
    ///
    /// This handler is only called if the enable clousure
    /// returned `true`.
    fn capture(&mut self, pkt: PcapEnvelope<'_>) -> Result<()>;

    /// A setup handler called once, when the subscriber becomes active.
    ///
    /// The default configuration takes no actions.
    fn open(&mut self) -> Result<()> {
        Ok(())
    }

    /// A teardown handler called once, when the subscriber will be deactivated.
    ///
    /// The default configuration takes no actions.
    fn close(&mut self) -> Result<()> {
        Ok(())
    }
}

/// Points in the packet flow, where libpcap may
/// capture traffic.
#[derive(Debug, Clone, Copy)]
pub enum PcapCapturePoint {
    /// Captures valid link layer traffic on all interfaces
    Ingress,
    /// Captures all output traffic from all interfaces.
    Egress,
}

/// A captured packetage, and associated metadata.
pub struct PcapEnvelope<'a> {
    /// An indicator of the capture point of this message.
    pub capture: PcapCapturePoint,
    /// A reference to the captured packet
    pub message: &'a Message,
    /// The receiving / sending interface for the packet.
    pub iface: &'a Interface,
}

impl Pcap {
    const fn new() -> Self {
        Pcap {
            mapping: Vec::new(),
        }
    }

    fn register(&mut self, id: ModuleId, deamon: Box<dyn PcapSubscriber>) {
        match self.mapping.binary_search_by(|e| e.0 .0.cmp(&id.0)) {
            Ok(i) | Err(i) => self.mapping.insert(i, (id, deamon)),
        }

        let Some(pcap) = self.deamon(module_id()) else {
            return;
        };
        try_warn!(pcap.open());
    }

    fn close(&mut self, id: ModuleId) {
        let Some(pcap) = self.deamon(id) else {
            return;
        };

        try_warn!(pcap.close());

        self.mapping.retain(|e| e.0 != id);
    }

    fn deamon(&mut self, id: ModuleId) -> Option<&mut dyn PcapSubscriber> {
        match self.mapping.binary_search_by(|e| e.0 .0.cmp(&id.0)) {
            Ok(i) => Some(&mut *self.mapping[i].1),
            Err(_) => None,
        }
    }

    fn capture(&mut self, envelope: PcapEnvelope<'_>) {
        let Some(pcap) = self.deamon(module_id()) else {
            return;
        };

        if pcap.enable_capture(envelope.capture) {
            try_warn!(pcap.capture(envelope));
        }
    }
}

/// Sets the PCAP subscriber for this network node.
pub fn set_pcap_deamon(deamon: impl PcapSubscriber + 'static) {
    let deamon = Box::new(deamon);
    LIBPCAP.with(|pcap| pcap.borrow_mut().register(module_id(), deamon));
}

pub(crate) fn capture(envelope: PcapEnvelope<'_>) {
    LIBPCAP.with(|pcap| pcap.borrow_mut().capture(envelope))
}

pub(crate) fn close(id: ModuleId) {
    LIBPCAP.with(|pcap| pcap.borrow_mut().close(id))
}
