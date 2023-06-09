use std::{
    fmt::Debug,
    io::{Error, ErrorKind, Result, Write},
    ops::Deref,
};

use des::prelude::{Message, MessageKind};
use inet_types::ip::IpPacketRef;

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
        capture: PcapCapturePoints::None,
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

pub(super) struct Null;
impl Write for Null {
    fn write(&mut self, _buf: &[u8]) -> Result<usize> {
        Err(Error::new(
            ErrorKind::BrokenPipe,
            "did not set a output for pcap",
        ))
    }
    fn flush(&mut self) -> Result<()> {
        Err(Error::new(
            ErrorKind::BrokenPipe,
            "did not set a output for pcap",
        ))
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
pub enum PcapCapturePoints {
    None,
    Ingress,
    Egress,
    #[default]
    All,
}
