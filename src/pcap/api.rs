use std::fmt::Debug;
use std::io::{BufWriter, Result, Write};
use std::ops::Add;
use std::slice;

use des::prelude::{Message, MessageKind};
use inet_types::ip::IpPacketRef;

use crate::IOContext;

use super::Null;

pub struct PcapConfig<W> {
    pub filters: PcapFilters,
    pub capture: PcapCapturePoints,
    pub output: W,
}
impl<W> PcapConfig<W> {
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

impl FromIterator<PcapFilter> for PcapFilters {
    fn from_iter<T: IntoIterator<Item = PcapFilter>>(iter: T) -> Self {
        PcapFilters {
            filters: Vec::from_iter(iter),
        }
    }
}

impl<'a> IntoIterator for &'a PcapFilters {
    type Item = &'a PcapFilter;
    type IntoIter = slice::Iter<'a, PcapFilter>;
    fn into_iter(self) -> Self::IntoIter {
        self.filters.iter()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PcapFilter {
    DenyEthertype(MessageKind),
    DenyIpProto(u8),
    DenyAll,

    AllowEthertype(MessageKind),
    AllowIpProto(u8),
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PcapCapturePoints {
    byte: u8,
}

const CAPTURE_L2_INCOMING: u8 = 0b1;
const CAPTURE_L2_OUTGOING: u8 = 0b10;
const CAPTURE_L3_INCOMING: u8 = 0b100;
const CAPTURE_L3_TRANSIT: u8 = 0b1000;

impl PcapCapturePoints {
    pub const NULL: PcapCapturePoints = PcapCapturePoints { byte: 0 };
    pub const CLIENT_DEFAULT: PcapCapturePoints = PcapCapturePoints {
        byte: CAPTURE_L2_INCOMING | CAPTURE_L2_OUTGOING,
    };
    pub const TRANSIT: PcapCapturePoints = PcapCapturePoints {
        byte: CAPTURE_L3_TRANSIT,
    };

    pub fn capture_l2_incoming(&self) -> bool {
        (self.byte & CAPTURE_L2_INCOMING) != 0
    }

    pub fn capture_l2_outgoing(&self) -> bool {
        (self.byte & CAPTURE_L2_OUTGOING) != 0
    }

    pub fn capture_l3_incoming(&self) -> bool {
        (self.byte & CAPTURE_L3_INCOMING) != 0
    }

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

// Opens a pcap debugger
pub fn pcap<W>(cfg: PcapConfig<W>) -> Result<()>
where
    W: Write + 'static,
{
    IOContext::with_current(|ctx| {
        let mut pcap = ctx.pcap.borrow_mut();
        pcap.output = BufWriter::new(Box::new(cfg.output));
        pcap.capture = cfg.capture;
        pcap.filters = cfg.filters;
        pcap.ifaces.clear();
        pcap.write_shb()?;

        Ok(())
    })
}
