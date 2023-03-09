use super::{Fd, IOContext, Socket, SocketDomain, SocketType};
use std::{io::Result, net::SocketAddr};

/// socket - create an endpoint for communication.
///
/// [socket] creates an endpoint for communication and returns a file
/// descriptor that refers to that endpoint.  The file descriptor
/// returned by a successful call will be the lowest-numbered file
/// descriptor not currently open for the process.
///
/// The domain argument specifies a communication domain; this
/// selects the protocol family which will be used for communication.
/// See [SocketDomain] for a list of valid domains.
///
/// The socket has the indicated type, which specifies the
/// communication semantics. See [SocketType] for a list of valid domains.
///
/// The protocol specifies a particular protocol to be used with the
/// socket.  Normally only a single protocol exists to support a
/// particular socket type within a given protocol family, in which
/// case protocol can be specified as 0.  However, it is possible
/// that many protocols may exist, in which case a particular
/// protocol must be specified in this manner.  The protocol number
/// to use is specific to the “communication domain” in which
/// communication is to take place.
pub fn socket(domain: SocketDomain, typ: SocketType, protocol: i32) -> Result<Fd> {
    IOContext::with_current(|ctx| ctx.create_socket(domain, typ, protocol))
}

/// bind - bind name to a socket.
///
/// When a socket is created with [socket], it exists in a name
/// space (address family) but has no address assigned to it. [bind]
/// assigns the address specified by addr to the socket referred to
/// by the file descriptor sockfd.
/// Traditionally, this operation is called "assigning a name to a
/// socket".
///
/// It is normally necessary to assign a local address using bind()
/// before a SOCK_STREAM socket may receive connections.
pub fn bind(sockfd: Fd, addr: SocketAddr) -> Result<()> {
    IOContext::with_current(|ctx| ctx.bind_socket(sockfd, addr))?;
    Ok(())
}

/// close - close a file descriptor
///
/// [close] closes a file descriptor, so that it no longer refers to
/// any file and may be reused.  Any record locks held
/// on the file it was associated with, and owned by the process, are
/// removed (regardless of the file descriptor that was used to
/// obtain the lock).
pub fn close(fd: Fd) -> Result<()> {
    IOContext::with_current(|ctx| ctx.close_socket(fd))
}

#[doc(hidden)]
pub fn bsd_socket_info(fd: Fd) -> Option<Socket> {
    IOContext::with_current(|ctx| ctx.sockets.get(&fd).cloned())
}
