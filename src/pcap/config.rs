use std::{
    fmt::Debug,
    io::Write,
    ops::{Add, Deref},
};

use des::prelude::{Message, MessageKind};
use inet_types::ip::IpPacketRef;

use super::Null;

/// A set of configurations who to probe packet from the underlying
/// mechanisms.
pub struct PcapConfig<W> {
    /// Filters are per-packet clousures that deny/allow packets
    /// to be captured.
    pub filters: PcapFilters,
    /// Capture points indicate the stage at which packets may be
    /// captured. E.g. `CLIENT_DEFAULT` captures all incoming
    /// and outgoing packet on the linklayer.
    pub capture: PcapCapturePoints,
    /// The output to which the captures are written in the
    /// PCAPNG file format.
    pub output: W,
}

impl<W> PcapConfig<W> {
    /// The default configuration, that represent a decaticvated instance
    /// of PCAP.
    pub const DISABLED: PcapConfig<&'static dyn Write> = PcapConfig {
        filters: PcapFilters {
            filters: Vec::new(),
        },
        capture: PcapCapturePoints::NULL,
        output: &Null,
    };
}

impl<W> Debug for PcapConfig<W> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PcapConfig")
            .field("capture", &self.capture)
            .finish()
    }
}

/// A set of filters, used for per-packet marking
/// whether to capture or ignore packets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PcapFilters {
    filters: Vec<PcapFilter>,
}

impl Default for PcapFilters {
    fn default() -> Self {
        PcapFilters {
            filters: vec![PcapFilter::AllowAll],
        }
    }
}

impl From<Vec<PcapFilter>> for PcapFilters {
    fn from(filters: Vec<PcapFilter>) -> Self {
        PcapFilters { filters }
    }
}

impl FromIterator<PcapFilter> for PcapFilters {
    fn from_iter<T: IntoIterator<Item = PcapFilter>>(iter: T) -> Self {
        PcapFilters {
            filters: Vec::from_iter(iter),
        }
    }
}

impl Deref for PcapFilters {
    type Target = [PcapFilter];
    fn deref(&self) -> &Self::Target {
        &self.filters
    }
}

/// A filtering condition whether to capture
/// or ignore a in-stream packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PcapFilter {
    /// This option will deny all ethernet packets containing
    /// the provided ethertype in its header.
    DenyEthertype(MessageKind),
    /// This option will deny all ip packets with
    /// a certain proto/next_header.
    DenyIpProto(u8),
    /// This option will deny all packet that have not
    /// been explicitly allowed.
    DenyAll,

    /// This option will allow and mark all ethernet packets containing
    /// the provided ethertype in its header.
    AllowEthertype(MessageKind),
    /// This option will allow and mark all ip packets with
    /// a certain proto/next_header.
    AllowIpProto(u8),
    /// This option will allow all packet that have not
    /// been explicitly denied.
    AllowAll,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum FilterResult {
    Allow,
    Deny,
    Continue,
}

impl PcapFilter {
    pub(super) fn evaluate_l2(&self, prev: FilterResult, msg: &Message) -> FilterResult {
        match self {
            Self::DenyEthertype(typ) => {
                if msg.header().kind == *typ {
                    FilterResult::Deny
                } else {
                    prev
                }
            }
            Self::AllowEthertype(typ) => {
                if msg.header().kind == *typ && prev != FilterResult::Deny {
                    FilterResult::Allow
                } else {
                    prev
                }
            }
            _ => prev,
        }
    }

    pub(super) fn evaluate_l3(&self, prev: FilterResult, msg: &IpPacketRef) -> FilterResult {
        match self {
            Self::DenyIpProto(proto) => {
                if msg.tos() == *proto {
                    FilterResult::Deny
                } else {
                    prev
                }
            }
            Self::AllowIpProto(proto) => {
                if msg.tos() == *proto && prev != FilterResult::Deny {
                    FilterResult::Allow
                } else {
                    prev
                }
            }
            _ => prev,
        }
    }

    pub(super) fn evaluate_fin(&self, prev: FilterResult) -> FilterResult {
        match self {
            Self::AllowAll => {
                if prev != FilterResult::Deny {
                    FilterResult::Allow
                } else {
                    prev
                }
            }
            Self::DenyAll => {
                if prev != FilterResult::Allow {
                    FilterResult::Deny
                } else {
                    prev
                }
            }
            _ => prev,
        }
    }
}

/// A capture configuration, where to capture in-stream packets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PcapCapturePoints {
    byte: u8,
}

const CAPTURE_L2_INCOMING: u8 = 0b1;
const CAPTURE_L2_OUTGOING: u8 = 0b10;
const CAPTURE_L3_INCOMING: u8 = 0b100;
const CAPTURE_L3_OUTGOING: u8 = 0b1000;
const CAPTURE_L3_TRANSIT: u8 = 0b10000;

impl PcapCapturePoints {
    /// This configuration will capture no packets at all.
    pub const NULL: PcapCapturePoints = PcapCapturePoints { byte: 0 };

    /// This configuration will capture all incoming and outgoing
    /// traffic on the linklayer. Usefull for clients, but routers
    /// may capture routed traffic twice.
    pub const CLIENT_DEFAULT: PcapCapturePoints = PcapCapturePoints {
        byte: CAPTURE_L2_INCOMING | CAPTURE_L2_OUTGOING,
    };

    /// This configuration will only capture networking layer
    /// transit traffic.
    pub const TRANSIT: PcapCapturePoints = PcapCapturePoints {
        byte: CAPTURE_L3_TRANSIT,
    };

    /// Whether to capture incoming linklayer packets.
    pub fn capture_l2_incoming(&self) -> bool {
        (self.byte & CAPTURE_L2_INCOMING) != 0
    }

    /// Whether to capture outgoing linklayer packets.
    pub fn capture_l2_outgoing(&self) -> bool {
        (self.byte & CAPTURE_L2_OUTGOING) != 0
    }

    /// Whether to capture incoming networking layer packets.
    pub fn capture_l3_incoming(&self) -> bool {
        (self.byte & CAPTURE_L3_INCOMING) != 0
    }

    /// Whether to capture outgoing networking layer packets.
    pub fn capture_l3_outgoing(&self) -> bool {
        (self.byte & CAPTURE_L3_OUTGOING) != 0
    }

    /// Whether to capture  networking layer transit traffic.
    pub fn capture_l3_transit(&self) -> bool {
        (self.byte & CAPTURE_L3_TRANSIT) != 0
    }
}

impl Add for PcapCapturePoints {
    type Output = Self;
    fn add(self, rhs: Self) -> Self::Output {
        PcapCapturePoints {
            byte: self.byte | rhs.byte,
        }
    }
}
