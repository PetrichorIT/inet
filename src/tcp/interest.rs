use std::{
    future::Future,
    io::{Error, ErrorKind, Result},
    task::{Poll, Waker},
};

use des::tokio::io::{Interest, Ready};

use crate::{socket::Fd, IOContext};

use super::types::TcpState;

#[derive(Debug, Clone)]
pub(crate) enum TcpInterest {
    TcpAccept(Fd),
    // TcpConnect(Fd),
    TcpRead(Fd),
    TcpWrite(Fd),
}

#[derive(Debug, Clone)]
pub(crate) struct TcpInterestGuard {
    pub(crate) interest: TcpInterest,
    pub(crate) waker: Waker,
}

impl TcpInterest {
    pub(crate) fn from_tokio(fd: Fd, interest: Interest) -> Self {
        if interest.is_readable() {
            return TcpInterest::TcpRead(fd);
        }
        if interest.is_writable() {
            return TcpInterest::TcpWrite(fd);
        }

        unimplemented!()
    }
}

impl TcpInterestGuard {
    pub(super) fn wake(self) {
        self.waker.wake()
    }
}

impl Future for TcpInterest {
    type Output = Result<Ready>;

    fn poll(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        match *self {
            // == TCP ==
            TcpInterest::TcpAccept(fd) => IOContext::with_current(|ctx| {
                if let Some(handle) = ctx.tcp.binds.get_mut(&fd) {
                    if handle.incoming.is_empty() {
                        handle.interests.push(TcpInterestGuard {
                            interest: self.clone(),
                            waker: cx.waker().clone(),
                        });
                        Poll::Pending
                    } else {
                        Poll::Ready(Ok(Ready::ALL))
                    }
                } else {
                    Poll::Ready(Err(Error::new(
                        ErrorKind::Other,
                        "Simulation context has dropped TcpListener",
                    )))
                }
            }),

            // TcpInterest::TcpEstablished(fd) => IOContext::with_current(|ctx| {
            //     let Some(handle) = ctx.tcp.streams.get_mut(&fd) else {
            //         return Poll::Ready(Err(Error::new(
            //             ErrorKind::InvalidInput,
            //             "socket dropped - invalid fd",
            //         )));
            //     };

            //     if handle.syn_resend_counter >= 3 {
            //         return Poll::Ready(Err(Error::new(
            //             ErrorKind::NotFound,
            //             "host not found - syn exceeded",
            //         )));
            //     }

            //     if handle.state as u8 >= TcpState::Established as u8 {
            //         Poll::Ready(Ok(Ready::ALL))
            //     } else {
            //         handle.established_interest = Some(cx.waker().clone());

            //         Poll::Pending
            //     }
            // }),
            TcpInterest::TcpRead(fd) => IOContext::with_current(|ctx| {
                let Some(handle) = ctx.tcp.streams.get_mut(&fd) else {
                    return Poll::Ready(Err(Error::new(
                        ErrorKind::InvalidInput,
                        "socket dropped - invalid fd",
                    )));
                };

                if handle.rx_buffer.len_continous() > 0 {
                    Poll::Ready(Ok(Ready::READABLE))
                } else {
                    if handle.no_more_data_closed() {
                        return Poll::Ready(Err(Error::new(ErrorKind::Other, "socket closed")));
                    }

                    handle.rx_read_interests.push(TcpInterestGuard {
                        interest: self.clone(),
                        waker: cx.waker().clone(),
                    });
                    Poll::Pending
                }
            }),

            TcpInterest::TcpWrite(fd) => IOContext::with_current(|ctx| {
                let Some(handle) = ctx.tcp.streams.get_mut(&fd) else {
                    return Poll::Ready(Err(Error::new(
                        ErrorKind::InvalidInput,
                        "socket dropped - invalid fd",
                    )));
                };

                if handle.tx_buffer.rem() > 0 {
                    Poll::Ready(Ok(Ready::WRITABLE))
                } else {
                    handle.tx_write_interests.push(TcpInterestGuard {
                        interest: self.clone(),
                        waker: cx.waker().clone(),
                    });
                    Poll::Pending
                }
            }),

            _ => Poll::Pending,
        }
    }
}
