// use crate::io::ready::Ready;

use std::fmt;
use std::ops;

/// Readiness event interest.
///
/// Specifies the readiness events the caller is interested in when awaiting on
/// I/O resource readiness states.
#[cfg_attr(docsrs, doc(cfg(feature = "net")))]
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct Interest(MioInterest);

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum MioInterest {
    READABLE,
    WRITABLE,
    BOTH,
}

impl Interest {
    /// Interest in all readable events.
    ///
    /// Readable interest includes read-closed events.
    pub const READABLE: Interest = Interest(MioInterest::READABLE);

    /// Interest in all writable events.
    ///
    /// Writable interest includes write-closed events.
    pub const WRITABLE: Interest = Interest(MioInterest::WRITABLE);

    /// Returns true if the value includes readable interest.
    ///
    /// # Examples
    ///
    /// ```
    /// use inet::io::Interest;
    ///
    /// assert!(Interest::READABLE.is_readable());
    /// assert!(!Interest::WRITABLE.is_readable());
    ///
    /// let both = Interest::READABLE | Interest::WRITABLE;
    /// assert!(both.is_readable());
    /// ```
    pub const fn is_readable(self) -> bool {
        matches!(self.0, MioInterest::READABLE | MioInterest::BOTH)
    }

    /// Returns true if the value includes writable interest.
    ///
    /// # Examples
    ///
    /// ```
    /// use inet::io::Interest;
    ///
    /// assert!(!Interest::READABLE.is_writable());
    /// assert!(Interest::WRITABLE.is_writable());
    ///
    /// let both = Interest::READABLE | Interest::WRITABLE;
    /// assert!(both.is_writable());
    /// ```
    pub const fn is_writable(self) -> bool {
        matches!(self.0, MioInterest::WRITABLE | MioInterest::BOTH)
    }

    /// Add together two `Interest` values.
    ///
    /// This function works from a `const` context.
    ///
    /// # Examples
    ///
    /// ```
    /// use inet::io::Interest;
    ///
    /// const BOTH: Interest = Interest::READABLE.add(Interest::WRITABLE);
    ///
    /// assert!(BOTH.is_readable());
    /// assert!(BOTH.is_writable());
    pub const fn add(self, other: Interest) -> Interest {
        Interest(match (self.0, other.0) {
            (MioInterest::READABLE, MioInterest::READABLE) => MioInterest::READABLE,
            (MioInterest::WRITABLE, MioInterest::WRITABLE) => MioInterest::WRITABLE,
            _ => MioInterest::BOTH,
        })
    }

    // pub(crate) fn mask(self) -> Ready {
    //     match self {
    //         Interest::READABLE => Ready::READABLE | Ready::READ_CLOSED,
    //         Interest::WRITABLE => Ready::WRITABLE | Ready::WRITE_CLOSED,
    //         _ => Ready::EMPTY,
    //     }
    // }
}

impl ops::BitOr for Interest {
    type Output = Self;

    #[inline]
    fn bitor(self, other: Self) -> Self {
        self.add(other)
    }
}

impl ops::BitOrAssign for Interest {
    #[inline]
    fn bitor_assign(&mut self, other: Self) {
        self.0 = (*self | other).0;
    }
}

impl fmt::Debug for Interest {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(fmt)
    }
}
