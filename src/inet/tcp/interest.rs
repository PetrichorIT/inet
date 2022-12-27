use std::{
    future::Future,
    io::{Error, ErrorKind, Result},
    task::{Poll, Waker},
};

use crate::inet::{Fd, IOContext};

use super::types::TcpState;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) enum TcpInterest {
    TcpAccept(Fd),
    TcpEstablished(Fd),
    // TcpConnect(Fd),
}

#[derive(Debug, Clone)]
pub(crate) struct TcpInterestGuard {
    pub(crate) interest: TcpInterest,
    pub(crate) waker: Waker,
}

impl Future for TcpInterest {
    type Output = Result<()>;

    fn poll(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        match *self {
            // == TCP ==
            TcpInterest::TcpAccept(fd) => IOContext::with_current(|ctx| {
                if let Some(handle) = ctx.tcp_listeners.get_mut(&fd) {
                    if handle.incoming.is_empty() {
                        handle.interests.push(TcpInterestGuard {
                            interest: self.clone(),
                            waker: cx.waker().clone(),
                        });

                        Poll::Pending
                    } else {
                        Poll::Ready(Ok(()))
                    }
                } else {
                    Poll::Ready(Err(Error::new(
                        ErrorKind::Other,
                        "Simulation context has dropped TcpListener",
                    )))
                }
            }),

            TcpInterest::TcpEstablished(fd) => IOContext::with_current(|ctx| {
                let Some(handle) = ctx.tcp_manager.get_mut(&fd) else {
                    // println!("0x{fd:x}");
                    return Poll::Ready(Err(Error::new(
                        ErrorKind::InvalidInput,
                        "socket dropped - invalid fd",
                    )));
                };

                if handle.state as u8 >= TcpState::Established as u8 {
                    Poll::Ready(Ok(()))
                } else {
                    handle.established_interest = Some(cx.waker().clone());

                    Poll::Pending
                }
            }),
        }
    }
}
