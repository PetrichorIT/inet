use std::{
    future::Future,
    io::{Error, ErrorKind},
    task::Poll,
};

use crate::io::{self, Ready};
use crate::{IOContext, socket::Fd};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct TcpInterest {
    pub fd: Fd,
    pub interest: io::Interest,
}

impl TcpInterest {
    pub(super) fn write(fd: Fd) -> Self {
        Self {
            fd,
            interest: io::Interest::WRITABLE,
        }
    }

    pub(crate) fn from_io(fd: Fd, interest: io::Interest) -> Self {
        Self { fd, interest }
    }
}

impl Future for TcpInterest {
    type Output = Result<Ready, Error>;

    fn poll(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        IOContext::with_current(|ctx| {
            let Some(handle) = ctx.tcp.streams.get_mut(&self.fd) else {
                return Poll::Ready(Err(Error::new(
                    ErrorKind::InvalidInput,
                    "socket dropped - invalid fd",
                )));
            };

            if let Some(err) = handle.interface.error() {
                return Poll::Ready(Err(err));
            }

            if handle.can_service(self.interest) {
                Poll::Ready(Ok(Ready::from_interest(self.interest)))
            } else {
                // TODO: Maybe Err no more data
                handle.interface.register(self.interest, cx);
                Poll::Pending
            }
        })
    }
}
