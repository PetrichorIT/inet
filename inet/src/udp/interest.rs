use std::io::{Error, ErrorKind, Result};
use std::task::Poll;
use std::{future::Future, task::Waker};

use crate::io::{Interest, Ready};
use crate::socket::Fd;
use crate::IOContext;

// TODO: cancelation safety
// - this interest is currently cancellation safe, but does not remove the enqued waker on drop

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpInterest {
    pub(crate) fd: Fd,
    pub(crate) io_interest: Interest,
    pub(crate) resolved: bool,
}

#[derive(Debug, Clone)]
pub struct UdpInterestGuard {
    waker: Waker,
}

impl UdpInterestGuard {
    pub(crate) fn wake(self) {
        self.waker.wake();
    }
}

impl Future for UdpInterest {
    type Output = Result<Ready>;
    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Self::Output> {
        if self.io_interest.is_readable() {
            return IOContext::with_current(|ctx| {
                let Some(socket) = ctx.udp.binds.get_mut(&self.fd) else {
                    self.resolved = true;
                    return Poll::Ready(Err(Error::new(
                        ErrorKind::InvalidInput,
                        "invalid fd - socket dropped",
                    )));
                };

                if socket.incoming.is_empty() {
                    socket.read_interest.push(UdpInterestGuard {
                        waker: cx.waker().clone(),
                    });

                    Poll::Pending
                } else {
                    self.resolved = true;
                    Poll::Ready(Ok(Ready::READABLE))
                }
            });
        }

        if self.io_interest.is_writable() {
            return IOContext::with_current(|ctx| {
                let Some(socket) = ctx.sockets.get(&self.fd) else {
                    self.resolved = true;
                    return Poll::Ready(Err(Error::new(
                        ErrorKind::InvalidInput,
                        "invalid fd - socket dropped",
                    )));
                };

                let Some(udp) = ctx.udp.binds.get_mut(&self.fd) else {
                    self.resolved = true;
                    return Poll::Ready(Err(Error::new(
                        ErrorKind::InvalidInput,
                        "invalid fd - socket dropped",
                    )));
                };

                let Some(interface) = ctx.ifaces.get_mut(&socket.interface.unwrap_ifid()) else {
                    self.resolved = true;
                    return Poll::Ready(Err(Error::new(ErrorKind::InvalidInput, "interface down")));
                };

                if interface.is_busy() {
                    interface.add_write_interest(self.fd);
                    udp.write_interest.push(UdpInterestGuard {
                        waker: cx.waker().clone(),
                    });
                    return Poll::Pending;
                }

                self.resolved = true;
                Poll::Ready(Ok(Ready::WRITABLE))
            });
        }

        self.resolved = true;
        Poll::Ready(Err(Error::new(
            ErrorKind::InvalidInput,
            "invalid interest without read or write components",
        )))
    }
}
