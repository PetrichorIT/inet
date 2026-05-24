use std::io::{Error, ErrorKind, Result};
use std::task::Poll;
use std::{future::Future, task::Waker};

use crate::IOHandle;
use crate::io::{Interest, Ready};
use crate::socket::Fd;

// TODO: cancelation safety
// - this interest is currently cancellation safe, but does not remove the enqued waker on drop

#[derive(Debug, Clone)]
pub struct UdpInterest {
    pub(crate) handle: IOHandle,
    pub(crate) fd: Fd,
    pub(crate) io_interest: Interest,
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
    fn poll(self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        if self.io_interest.is_readable() {
            return self.handle.clone().do_mutating(|ctx| {
                let socket = ctx.udp.get_mut(self.fd)?;
                if socket.incoming.is_empty() {
                    socket.read_interest.push(UdpInterestGuard {
                        waker: cx.waker().clone(),
                    });

                    Poll::Pending
                } else {
                    Poll::Ready(Ok(Ready::READABLE))
                }
            });
        }

        if self.io_interest.is_writable() {
            return self.handle.clone().do_mutating(|ctx| {
                // assert(fd is valid UDP socket)

                let id = ctx.iface_for_write_intention(self.fd)?;
                let interface = ctx.ifaces.get_mut(&id).unwrap();

                if interface.is_busy() {
                    interface.add_write_interest(self.fd);
                    let socket = ctx.udp.get_mut(self.fd)?;
                    socket.write_interest.push(UdpInterestGuard {
                        waker: cx.waker().clone(),
                    });
                    return Poll::Pending;
                }

                Poll::Ready(Ok(Ready::WRITABLE))
            });
        }

        Poll::Ready(Err(Error::new(
            ErrorKind::InvalidInput,
            "invalid interest without read or write components",
        )))
    }
}
