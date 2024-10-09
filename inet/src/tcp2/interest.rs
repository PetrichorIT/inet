use std::{
    future::Future,
    io::{Error, ErrorKind},
    task::Poll,
};

use tracing::instrument::WithSubscriber;

use crate::io::Ready;
use crate::{socket::Fd, IOContext};

#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq)]
pub(super) enum TcpInterest {
    Read(Fd),
    Write(Fd),
}

impl TcpInterest {
    pub(crate) fn from_tokio(fd: Fd, interest: crate::io::Interest) -> Self {
        if interest.is_readable() {
            return Self::Read(fd);
        }
        if interest.is_writable() {
            return Self::Write(fd);
        }

        unimplemented!()
    }
}

impl Future for TcpInterest {
    type Output = Result<Ready, Error>;

    fn poll(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        match *self {
            Self::Read(fd) => IOContext::with_current(|ctx| {
                let Some(handle) = ctx.tcp2.streams.get_mut(&fd) else {
                    return Poll::Ready(Err(Error::new(
                        ErrorKind::InvalidInput,
                        "socket dropped - invalid fd",
                    )));
                };

                if let Some(err) = handle.error.take() {
                    return Poll::Ready(Err(err));
                }

                if handle.is_readable() {
                    tracing::trace!("resolved read interest");
                    Poll::Ready(Ok(Ready::READABLE))
                } else {
                    // TODO: Maybe Err no more data
                    handle.rx_wakers.push(cx.waker().clone());
                    Poll::Pending
                }
            }),

            Self::Write(fd) => IOContext::with_current(|ctx| {
                let Some(handle) = ctx.tcp2.streams.get_mut(&fd) else {
                    return Poll::Ready(Err(Error::new(
                        ErrorKind::InvalidInput,
                        "socket dropped - invalid fd",
                    )));
                };

                if let Some(err) = handle.error.take() {
                    return Poll::Ready(Err(err));
                }

                if handle.is_writable() {
                    tracing::trace!("resolved write interest");
                    Poll::Ready(Ok(Ready::WRITABLE))
                } else {
                    handle.tx_wakers.push(cx.waker().clone());
                    Poll::Pending
                }
            }),
        }
    }
}
