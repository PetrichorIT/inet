/// File descriptors.
pub type Fd = u32;

/// A trait to extract the raw file descriptor from an underlying object.
pub trait AsRawFd {
    /// Extracts the raw file descriptor.
    ///
    /// This function is typically used to borrow an owned file descriptor.
    /// When used in this way, this method does not pass ownership of the raw file descriptor
    /// to the caller, and the file descriptor is only guaranteed to be valid while the
    /// original object has not yet been destroyed.
    fn as_raw_fd(&self) -> Fd;
}

/// A trait to express the ability to construct an object from a raw file descriptor.
pub trait FromRawFd {
    /// Constructs a new instance of Self from the given raw file descriptor.
    ///
    /// This function is typically used to consume ownership of the specified file descriptor.
    /// When used in this way, the returned object will take responsibility for closing it
    /// when the object goes out of scope.
    fn from_raw_fd(fd: Fd) -> Self;
}

/// A trait to express the ability to consume an object and acquire ownership of its raw file descriptor.
pub trait IntoRawFd {
    /// Consumes this object, returning the raw underlying file descriptor.
    ///
    /// This function is typically used to transfer ownership of the underlying file descriptor to the caller.
    /// When used in this way, callers are then the unique owners of the file descriptor
    /// and must close it once it’s no longer needed.
    fn into_raw_fd(self) -> Fd;
}
