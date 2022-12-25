use std::io::{Error, ErrorKind, Result};
use std::task::Poll;
use std::{future::Future, task::Waker};

use crate::inet::{Fd, IOContext};
use tokio::io::{Interest, Ready};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpInterest {
    pub(crate) fd: Fd,
    pub(crate) interest: Interest,
}

#[derive(Debug, Clone)]
pub struct UdpInterestGuard {
    pub(crate) interest: UdpInterest,
    pub(crate) waker: Waker,
}

impl Future for UdpInterest {
    type Output = Result<Ready>;
    fn poll(self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        if self.interest.is_readable() {
            return IOContext::with_current(|ctx| {
                let Some(socket) = ctx.udp_manager.get_mut(&self.fd) else {
                    return Poll::Ready(Err(Error::new(ErrorKind::InvalidInput, "invalid fd - socket dropped")))
                };

                if socket.incoming.is_empty() {
                    socket.interest = Some(UdpInterestGuard {
                        interest: self.clone(),
                        waker: cx.waker().clone(),
                    });
                    Poll::Pending
                } else {
                    Poll::Ready(Ok(Ready::READABLE))
                }
            });
        }

        if self.interest.is_writable() {
            return IOContext::with_current(|ctx| {
                let Some(socket) = ctx.sockets.get(&self.fd) else {
                    return Poll::Ready(Err(Error::new(ErrorKind::InvalidInput, "invalid fd - socket dropped")))
                };

                let Some(udp) = ctx.udp_manager.get_mut(&self.fd) else {
                    return Poll::Ready(Err(Error::new(ErrorKind::InvalidInput, "invalid fd - socket dropped")))
                };

                let Some(interface) = ctx.interfaces.get_mut(&socket.interface) else {
                    return Poll::Ready(Err(Error::new(ErrorKind::InvalidInput, "interface down")))
                };

                if interface.is_busy() {
                    interface.add_write_interest(self.fd);
                    udp.interest = Some(UdpInterestGuard {
                        interest: self.clone(),
                        waker: cx.waker().clone(),
                    });

                    Poll::Pending
                } else {
                    Poll::Ready(Ok(Ready::WRITABLE))
                }
            });
        }

        Poll::Ready(Err(Error::new(
            ErrorKind::InvalidInput,
            "invalid interest without read or write components",
        )))
    }
}
