use des::prelude::*;
use std::{
    collections::hash_map,
    ffi::CStr,
    fmt,
    hash::{Hash, Hasher},
    ops::Deref,
    str::from_utf8,
};

use crate::socket::Fd;

pub(crate) const KIND_LINK_UPDATE: MessageKind = 0x0500;
pub(crate) const KIND_IO_TIMEOUT: MessageKind = 0x0128;

pub(crate) const ID_IPV6_TIMEOUT: MessageId = 0x8d66;

#[derive(Debug, Clone, PartialEq, Eq, Hash, MessageBody)]
pub(crate) struct LinkUpdate(pub IfId);

impl From<LinkUpdate> for Message {
    fn from(value: LinkUpdate) -> Self {
        Message::new().kind(KIND_LINK_UPDATE).content(value).build()
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, MessageBody)]
pub struct IfId {
    // byte 0..6 prefix
    // byte 7 hash
    bytes: [u8; 8],
}

impl IfId {
    pub const NULL: Self = Self { bytes: [0; 8] };
    pub const BROADCAST: Self = Self { bytes: [0xff; 8] };

    pub fn new(name: &str) -> Self {
        let mut bytes = [0u8; 8];
        let len = name.len().min(7);
        bytes[..len].copy_from_slice(&name.as_bytes()[..len]);

        let mut hasher = hash_map::DefaultHasher::new();
        name.hash(&mut hasher);
        let result = hasher.finish();

        // Subtract 48 to ensure that Id::new("") is [0; 8]
        bytes[7] = result.to_be_bytes()[0].wrapping_sub(48);

        Self { bytes }
    }

    pub fn matches(&self, name: &str) -> bool {
        Self::new(name) == *self
    }
}

impl fmt::Display for IfId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        <Self as fmt::Debug>::fmt(self, f)
    }
}

impl fmt::Debug for IfId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bytes = &self.bytes[..7];
        let cstr = CStr::from_bytes_until_nul(bytes);
        let str = match cstr {
            Ok(cstr) => cstr.to_str().unwrap(),
            Err(_) => from_utf8(bytes).unwrap(),
        };

        write!(f, "{str}")
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
    pub fn id(&self) -> IfId {
        self.id.clone()
    }

    /// Creates a new interface name from a string
    pub fn new(s: impl AsRef<str>) -> Self {
        let name = s.as_ref().to_string();
        Self {
            id: IfId::new(&name),
            name,
            parent: None,
        }
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

// # Interface Status

/// The activity status of a network interface
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum InterfaceStatus {
    /// The interface is active and can be used.
    ///
    /// This indicates the existence of the interface, but makes no assumtions
    /// whether the interface is currently free to send, or at all contected to any endpoint.
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
    /// The sender has no current work, thus sending will not be delayed.
    ///
    /// This means that any sending operation on this inteface, will send it's
    /// first packet unbuffered, thus without a chance of client-side loss.
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
        assert_eq!(IfId::new("en0").bytes[..7], b"en0\0\0\0\0"[..]);
        assert_eq!(IfId::new("eth0").bytes[..7], b"eth0\0\0\0"[..]);
        assert_eq!(IfId::new("abcdefg").bytes[..7], b"abcdefg"[..]);
        assert_eq!(IfId::new("interface-delta").bytes[..7], b"interfa"[..]);
        assert_eq!(IfId::new("").bytes[..7], b"\0\0\0\0\0\0\0"[..]);
    }

    #[test]
    fn iface_debug() {
        assert_eq!(IfId::new("en0").to_string(), "en0");
        assert_eq!(IfId::new("eth0").to_string(), "eth0");
        assert_eq!(IfId::new("").to_string(), "");
        assert_eq!(IfId::new("exactly").to_string(), "exactly");
        assert_eq!(IfId::new("overflow").to_string(), "overflo");
    }

    #[test]
    fn iface_id_nonrandom_hashing() {
        assert_eq!(IfId::new("en0"), IfId::new("en0"));
    }

    #[test]
    fn iface_id_special_cases() {
        assert_eq!(IfId::NULL, IfId::new(""));
    }
}
