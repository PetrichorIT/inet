use crate::io::Interest;
use bitflags::bitflags;

bitflags! {
    /// Describes the readiness state of an I/O resources.
    ///
    /// `Ready` tracks which operation an I/O resource is ready to perform.
    #[cfg_attr(docsrs, doc(cfg(feature = "net")))]
    #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
    pub struct Ready: u8 {
        const READABLE      = 0b0001;
        const WRITABLE      = 0b0010;
        const READ_CLOSED   = 0b0100;
        const WRITE_CLOSED  = 0b1000;
    }
}

impl Ready {
    /// Returns `true` if the value includes `readable`.
    ///
    /// # Examples
    ///
    /// ```
    /// use inet::io::Ready;
    ///
    /// assert!(!Ready::empty().is_readable());
    /// assert!(Ready::READABLE.is_readable());
    /// assert!(Ready::READ_CLOSED.is_readable());
    /// assert!(!Ready::WRITABLE.is_readable());
    /// ```
    pub fn is_readable(self) -> bool {
        self.contains(Ready::READABLE) || self.is_read_closed()
    }

    /// Returns `true` if the value includes writable `readiness`.
    ///
    /// # Examples
    ///
    /// ```
    /// use inet::io::Ready;
    ///
    /// assert!(!Ready::empty().is_writable());
    /// assert!(!Ready::READABLE.is_writable());
    /// assert!(Ready::WRITABLE.is_writable());
    /// assert!(Ready::WRITE_CLOSED.is_writable());
    /// ```
    pub fn is_writable(self) -> bool {
        self.contains(Ready::WRITABLE) || self.is_write_closed()
    }

    /// Returns `true` if the value includes read-closed `readiness`.
    ///
    /// # Examples
    ///
    /// ```
    /// use inet::io::Ready;
    ///
    /// assert!(!Ready::empty().is_read_closed());
    /// assert!(!Ready::READABLE.is_read_closed());
    /// assert!(Ready::READ_CLOSED.is_read_closed());
    /// ```
    pub fn is_read_closed(self) -> bool {
        self.contains(Ready::READ_CLOSED)
    }

    /// Returns `true` if the value includes write-closed `readiness`.
    ///
    /// # Examples
    ///
    /// ```
    /// use inet::io::Ready;
    ///
    /// assert!(!Ready::empty().is_write_closed());
    /// assert!(!Ready::WRITABLE.is_write_closed());
    /// assert!(Ready::WRITE_CLOSED.is_write_closed());
    /// ```
    pub fn is_write_closed(self) -> bool {
        self.contains(Ready::WRITE_CLOSED)
    }
}

// use crate::io::Interest;

impl Ready {
    pub(crate) fn from_interest(interest: Interest) -> Ready {
        let mut ready = Ready::empty();

        if interest.is_readable() {
            ready |= Ready::READABLE;
        }

        if interest.is_writable() {
            ready |= Ready::WRITABLE;
        }

        ready
    }
}
