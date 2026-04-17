use des::{MessageBody, prelude::*};
use serde::{Deserialize, Serialize};
use std::{
    ffi::CStr,
    fmt,
    hash::{DefaultHasher, Hash, Hasher},
    num::NonZeroU64,
    ops::Deref,
    str::from_utf8,
};
use valuable::Valuable;

use crate::socket::Fd;

pub(crate) const KIND_LINK_UPDATE: MessageKind = 0x0500;
pub(crate) const KIND_IO_TIMEOUT: MessageKind = 0x0128;

pub(crate) const ID_IPV6_TIMEOUT: MessageId = 0x8d66;

#[derive(Debug, Clone, PartialEq, Eq, Hash, MessageBody)]
pub(crate) struct LinkUpdate(pub IfId);

impl From<LinkUpdate> for Message {
    fn from(value: LinkUpdate) -> Self {
        Message::default()
            .with_kind(KIND_LINK_UPDATE)
            .with_content(value)
    }
}

/// An interface specifcation (either a concrete interface or none at all)
pub type IfSpec = Option<IfId>;

/// An interface identifer (unique per IO context).
#[derive(Clone, Copy, PartialEq, Eq, Hash, MessageBody, Valuable, Serialize, Deserialize)]
pub struct IfId {
    /// Encoded identifer for an interface
    /// -> 7 bytes encode the prefix of the interface name
    /// -> 1 bytes encodes a hash code for the entire name
    /// Stored as NonZeroU64 since [0; 8] is not possible exepct with name "" which is invalid
    /// -> allows memory optimizations for Option<T>
    bytes: NonZeroU64,
}

impl IfId {
    pub const UNKNOWN: Self = Self {
        bytes: NonZeroU64::MAX,
    };

    #[track_caller]
    pub fn new(name: &str) -> Self {
        assert!(!name.is_empty(), "does not allow empty names");
        assert!(name.is_ascii(), "can only encode assci values");

        let mut bytes = [0u8; 8];
        let len = name.len().min(7);
        bytes[..len].copy_from_slice(&name.as_bytes()[..len]);

        let mut hasher = DefaultHasher::new();
        name.hash(&mut hasher);
        bytes[7] = hasher.finish().to_be_bytes()[0];

        let bytes = NonZeroU64::new(u64::from_be_bytes(bytes)).expect("illegal state");

        Self { bytes }
    }

    #[inline]
    fn bytes(&self) -> [u8; 8] {
        self.bytes.get().to_be_bytes()
    }

    pub fn matches(&self, name: &str) -> bool {
        Self::new(name) == *self
    }
}

impl PartialEq<IfSpec> for IfId {
    fn eq(&self, other: &IfSpec) -> bool {
        Some(self) == other.as_ref()
    }
}

impl PartialEq<&str> for IfId {
    fn eq(&self, other: &&str) -> bool {
        // do not call IfId::new with invalid string
        !other.is_empty() && other.is_ascii() && *self == IfId::new(other)
    }
}

impl fmt::Display for IfId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        <Self as fmt::Debug>::fmt(self, f)
    }
}

impl fmt::Debug for IfId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bytes = &self.bytes()[..7];
        let cstr = CStr::from_bytes_until_nul(bytes);
        match cstr {
            Ok(cstr) => write!(f, "{}", cstr.to_string_lossy()),
            Err(_) => {
                let utf8 = from_utf8(bytes).expect("illegal state: str must be ascii");
                write!(f, "{utf8}")
            }
        }
    }
}

/// A name for a network interface
#[derive(Debug, Clone, PartialEq, Eq, Hash, Valuable, Serialize, Deserialize)]
pub struct InterfaceName {
    pub(crate) name: String,
    pub(crate) parent: Option<Box<InterfaceName>>,
}

impl InterfaceName {
    pub fn id(&self) -> IfId {
        IfId::new(&self.name)
    }

    /// Creates a new interface name from a string
    pub fn new(s: impl AsRef<str>) -> Self {
        let name = s.as_ref().to_string();
        Self { name, parent: None }
    }
}

impl Deref for InterfaceName {
    type Target = str;
    fn deref(&self) -> &Self::Target {
        &self.name
    }
}

impl fmt::Display for InterfaceName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(parent) = self.parent.as_ref() {
            write!(f, "{}:{}", parent, self.name)
        } else {
            write!(f, "{}", self.name)
        }
    }
}

impl<T: AsRef<str>> From<T> for InterfaceName {
    fn from(value: T) -> Self {
        Self::new(value)
    }
}

// # Busy state

/// The state of the interfaces sending half.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub enum InterfaceBusyState {
    /// The sender has no current work, thus sending will not be delayed.
    ///
    /// This means that any sending operation on this inteface, will send it's
    /// first packet unbuffered, thus without a chance of client-side loss.
    #[default]
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iface_id_encoding() {
        assert_eq!(IfId::new("en0").bytes()[..7], b"en0\0\0\0\0"[..]);
        assert_eq!(IfId::new("eth0").bytes()[..7], b"eth0\0\0\0"[..]);
        assert_eq!(IfId::new("abcdefg").bytes()[..7], b"abcdefg"[..]);
        assert_eq!(IfId::new("interface-delta").bytes()[..7], b"interfa"[..]);
    }

    #[test]
    fn iface_trunc_can_match_original() {
        assert!(IfId::new("interface-delta").matches("interface-delta"));
        assert!(!IfId::new("interface-delta").matches("interface-not-delta"));
    }

    #[test]
    fn iface_debug() {
        assert_eq!(IfId::new("en0").to_string(), "en0");
        assert_eq!(IfId::new("eth0").to_string(), "eth0");
        assert_eq!(IfId::new("exactly").to_string(), "exactly");
        assert_eq!(IfId::new("overflow").to_string(), "overflo");
    }

    #[test]
    fn iface_id_nonrandom_hashing() {
        assert_eq!(IfId::new("en0"), IfId::new("en0"));
    }
}
