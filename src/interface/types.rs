use des::prelude::*;
use std::fmt;

use crate::socket::Fd;

pub(crate) const KIND_LINK_UPDATE: MessageKind = 0x0500;
pub(crate) const KIND_IO_TIMEOUT: MessageKind = 0x0128;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, MessageBody)]
pub(crate) struct LinkUpdate(pub IfId);

impl From<LinkUpdate> for Message {
    fn from(value: LinkUpdate) -> Self {
        Message::new().kind(KIND_LINK_UPDATE).content(value).build()
    }
}

/// A numeric identifier derived from a interface name.
#[derive(Clone, Copy, PartialEq, Eq, Hash, MessageBody)]
#[repr(transparent)]
pub struct IfId(u64);

impl IfId {
    /// The invalid interface address, representing Option::\<IfId\>::None
    pub const NULL: IfId = IfId(0);
    /// The broadcast interface address, an alias for all active interfaces
    pub const BROADCAST: IfId = IfId(u64::MAX);
}

impl fmt::Debug for IfId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        <Self as fmt::Display>::fmt(self, f)
    }
}
impl fmt::Display for IfId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:x}", self.0)
    }
}

/// A name for a network interface
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct InterfaceName {
    pub(crate) name: String,
    pub(crate) id: IfId,
    pub(crate) parent: Option<Box<InterfaceName>>,
}

impl InterfaceName {
    /// Creates a new interface name from a string
    pub fn new(s: impl AsRef<str>) -> Self {
        let name = s.as_ref().to_string();
        let hash = hash!(name);
        Self {
            name,
            id: IfId(hash),
            parent: None,
        }
    }
}

impl fmt::Display for InterfaceName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(parent) = self.parent.as_ref() {
            write!(f, "{}:{}", parent, self.name)
        } else {
            self.name.fmt(f)
        }
    }
}

impl<T: AsRef<str>> From<T> for InterfaceName {
    fn from(value: T) -> Self {
        Self::new(value)
    }
}

// # Interface Status

/// The activity status of a network interface
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum InterfaceStatus {
    /// The interface is active and can be used.
    Active,
    /// The interface is only pre-configures not really there.
    #[default]
    Inactive,
}

impl fmt::Display for InterfaceStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> std::result::Result<(), fmt::Error> {
        match self {
            Self::Active => write!(f, "active"),
            Self::Inactive => write!(f, "inactive"),
        }
    }
}

// # Busy state

/// The state of the interfaces sending half.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum InterfaceBusyState {
    /// The sender has no current work, thus sending will not be delayed
    Idle,
    /// The sender is currently sending a packet, and will be finished
    /// at the timepoint specified in `until`. All sockets with an interest
    /// in the upcoming statechange may register themself in `interests`.
    Busy { until: SimTime, interests: Vec<Fd> },
}

impl InterfaceBusyState {
    pub(super) fn merge_new(&mut self, new: InterfaceBusyState) {
        if let InterfaceBusyState::Busy { until, interests } = self {
            if let InterfaceBusyState::Busy {
                until: new_deadline,
                interests: new_intersts,
            } = new
            {
                *until = (*until).max(new_deadline);
                interests.extend(new_intersts)
            }
        } else {
            *self = new;
        }
    }
}
