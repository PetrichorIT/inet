use std::io::{Error, ErrorKind, Result};
use std::task::Poll;
use std::{future::Future, task::Waker};

use crate::io::{Interest, Ready};
use crate::socket::Fd;
use crate::IOContext;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpInterest {
    pub(crate) fd: Fd,
    pub(crate) io_interest: Interest,
    pub(crate) resolved: bool,
}

#[derive(Debug, Clone)]
pub struct UdpInterestGuard {
    interest: UdpInterest,
    waker: Waker,
}

impl UdpInterestGuard {
    pub(crate) fn wake(mut self) {
        self.interest.resolved = true;
        self.waker.wake_by_ref();
    }

    pub(crate) fn is_writable(&self) -> bool {
        self.interest.io_interest.is_writable()
    }

    pub(crate) fn is_readable(&self) -> bool {
        self.interest.io_interest.is_readable()
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
                    return Poll::Ready(Err(Error::new(ErrorKind::InvalidInput, "invalid fd - socket dropped")))
                };

                if socket.incoming.is_empty() {
                    socket.interest.replace(UdpInterestGuard {
                        interest: self.clone(),
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
                    return Poll::Ready(Err(Error::new(ErrorKind::InvalidInput, "invalid fd - socket dropped")))
                };

                let Some(udp) = ctx.udp.binds.get_mut(&self.fd) else {
                    self.resolved = true;
                    return Poll::Ready(Err(Error::new(ErrorKind::InvalidInput, "invalid fd - socket dropped")))
                };

                let Some(interface) = ctx.ifaces.get_mut(&socket.interface.unwrap_ifid()) else {
                    self.resolved = true;
                    return Poll::Ready(Err(Error::new(ErrorKind::InvalidInput, "interface down")))
                };

                if interface.is_busy() {
                    interface.add_write_interest(self.fd);
                    udp.interest.replace(UdpInterestGuard {
                        interest: self.clone(),
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

impl Drop for UdpInterest {
    fn drop(&mut self) {
        if !self.resolved {
            if self.io_interest.is_readable() || self.io_interest.is_writable() {
                IOContext::try_with_current(|ctx| {
                    if let Some(udp) = ctx.udp.binds.get_mut(&self.fd) {
                        let _ = udp.interest.take();
                    }
                });
                return;
            }
        }
    }
}

impl Drop for UdpInterestGuard {
    fn drop(&mut self) {
        // prevent recursive calls of UdpInterest::drop that cause borrowmut of ctx
        self.interest.resolved = true;
    }
}
