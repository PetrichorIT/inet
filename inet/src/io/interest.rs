use bitflags::bitflags;

bitflags! {
    /// Readiness event interest.
    ///
    /// Specifies the readiness events the caller is interested in when awaiting on
    /// I/O resource readiness states.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct Interest: u8 {
        const READABLE = 0b01;
        const WRITABLE = 0b10;
        const BOTH = Self::READABLE.bits() | Self::WRITABLE.bits();
    }
}

impl Interest {
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
    pub const fn is_readable(&self) -> bool {
        self.contains(Interest::READABLE)
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
    pub const fn is_writable(&self) -> bool {
        self.contains(Interest::WRITABLE)
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
    pub const fn add(&self, other: Interest) -> Interest {
        Interest::from_bits_truncate(self.bits() | other.bits())
    }
}
