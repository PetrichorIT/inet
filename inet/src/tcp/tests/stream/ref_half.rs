use std::{
    pin::Pin,
    task::{Context, Poll},
};

use serial_test::serial;
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadBuf};

use crate::{
    tcp::{ReadHalf, TcpStream, tests::stream::accpet_any_incoming_and_echo_if_possible},
    utils::SimpleSim,
};

#[test]
#[serial]
fn as_ref() -> Result<(), des::net::Failure> {
    let mut sim = SimpleSim::default();

    fn req_actual_str(_s: &TcpStream) {}

    sim.node("192.168.2.111", || async move {
        accpet_any_incoming_and_echo_if_possible("0.0.0.0:80").await
    });

    sim.node_require_join("192.168.2.222", || async move {
        let mut org = TcpStream::connect("192.168.2.111:80").await?;
        let (r, w) = org.split();
        req_actual_str(r.as_ref());
        req_actual_str(w.as_ref());
        Ok(())
    });

    sim.run()
}

#[test]
#[serial]
fn parallel_read_and_write() -> Result<(), des::net::Failure> {
    let mut sim = SimpleSim::default();

    sim.node("192.168.2.111", || async move {
        accpet_any_incoming_and_echo_if_possible("0.0.0.0:80").await
    });

    sim.node_require_join("192.168.2.222", || async move {
        let mut org = TcpStream::connect("192.168.2.111:80").await?;
        let (mut r, mut w) = org.split();
        assert_eq!(r.local_addr()?, w.local_addr()?);
        assert_eq!(r.peer_addr()?, w.peer_addr()?);

        let mut acc = 0;
        while acc < 100_000 {
            w.writable().await?;
            acc += w.try_write(&[1; 1024])?;
        }

        w.write_all(&[1, 2, 3, 4]).await?;

        w.forget();

        // there should be more than enough echos data
        r.peek(&mut [0; 1024]).await?;
        r.readable().await?;
        r.try_read(&mut [0; 1024])?;

        r.read_exact(&mut [0; 42]).await?;

        Ok(())
    });

    sim.run()
}

#[test]
#[serial]
fn peeking() -> Result<(), des::net::Failure> {
    let mut sim = SimpleSim::default();

    sim.node("192.168.2.111", || async move {
        accpet_any_incoming_and_echo_if_possible("0.0.0.0:80").await
    });

    sim.node("192.168.2.222", || async move {
        let mut stream = TcpStream::connect("192.168.2.111:80").await?;
        let (r, w) = stream.split();

        let mut acc = 0;
        while acc < 100_000 {
            w.writable().await?;
            acc += w.try_write(&[1; 1024])?;
        }

        w.forget();

        struct Fut<'a>(ReadHalf<'a>);
        impl Future for Fut<'_> {
            type Output = ();
            fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
                let this = self.get_mut();
                this.0
                    .poll_peek(cx, &mut ReadBuf::new(&mut [0; 1024]))
                    .map(|_| ())
            }
        }

        Fut(r).await;

        Ok(())
    });

    sim.run()
}
