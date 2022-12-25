use std::io::{Error, ErrorKind, Result};
use std::task::Poll;
use std::{future::Future, task::Waker};

use crate::inet::{Fd, IOContext};
use tokio::io::{Interest, Ready};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpInterest {
    pub(super) fd: Fd,
    pub(super) interest: Interest,
}

#[derive(Debug, Clone)]
pub struct UdpInterestGuard {
    pub(super) interest: UdpInterest,
    pub(super) waker: Waker,
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
            return Poll::Ready(Ok(Ready::WRITABLE));
        }

        Poll::Ready(Err(Error::new(
            ErrorKind::InvalidInput,
            "invalid interest without read or write components",
        )))
    }
}
