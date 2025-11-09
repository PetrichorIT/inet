use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use des::runtime::RuntimeError;
use serial_test::serial;
use tokio::io::ReadBuf;

use crate::{
    tcp::{OwnedReadHalf, TcpStream, tests::stream::accpet_any_incoming_and_echo_if_possible},
    utils::SimpleSim,
};

#[test]
#[serial]
fn reunite() -> Result<(), RuntimeError> {
    let mut sim = SimpleSim::default();

    sim.node("192.168.2.111", || async move {
        accpet_any_incoming_and_echo_if_possible("0.0.0.0:80").await
    });

    sim.node_require_join("192.168.2.222", || async move {
        let stream = TcpStream::connect("192.168.2.111:80").await?;
        let (read, write) = stream.into_split();
        let _stream = read.reunite(write).map_err(|_| io::Error::other("error"))?;

        // reverse API
        let stream = TcpStream::connect("192.168.2.111:80").await?;
        let (read, write) = stream.into_split();
        let _ = write.reunite(read).map_err(|_| io::Error::other("error"))?;

        // Failure
        let a = TcpStream::connect("192.168.2.111:80").await?;
        let b = TcpStream::connect("192.168.2.111:80").await?;

        let (ar, aw) = a.into_split();
        let (br, bw) = b.into_split();

        let _ = ar.reunite(bw).expect_err("must fail is not the same");
        let _ = br.reunite(aw).expect_err("must fail is not the same");

        Ok(())
    });

    sim.run()
}

#[test]
#[serial]
fn parallel_read_and_write() -> Result<(), RuntimeError> {
    let mut sim = SimpleSim::default();

    sim.node("192.168.2.111", || async move {
        accpet_any_incoming_and_echo_if_possible("0.0.0.0:80").await
    });

    sim.node("192.168.2.222", || async move {
        let (r, w) = TcpStream::connect("192.168.2.111:80").await?.into_split();
        assert_eq!(r.local_addr()?, w.local_addr()?);
        assert_eq!(r.peer_addr()?, w.peer_addr()?);

        tokio::spawn(async move {
            loop {
                r.readable().await?;
                r.try_read(&mut [0; 1024])?;
            }
            #[allow(unreachable_code)]
            Ok::<(), io::Error>(())
        });

        let mut acc = 0;
        while acc < 100_000 {
            w.writable().await?;
            acc += w.try_write(&[1; 1024])?;
        }

        w.forget();

        Ok(())
    });

    sim.run()
}

#[test]
#[serial]
fn peeking() -> Result<(), RuntimeError> {
    let mut sim = SimpleSim::default();

    sim.node("192.168.2.111", || async move {
        accpet_any_incoming_and_echo_if_possible("0.0.0.0:80").await
    });

    sim.node("192.168.2.222", || async move {
        let (r, w) = TcpStream::connect("192.168.2.111:80").await?.into_split();
        assert_eq!(r.local_addr()?, w.local_addr()?);
        assert_eq!(r.peer_addr()?, w.peer_addr()?);

        tokio::spawn(async move {
            struct Fut<'a>(&'a OwnedReadHalf);
            impl Future for Fut<'_> {
                type Output = ();
                fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
                    let this = self.get_mut();
                    this.0
                        .poll_peek(cx, &mut ReadBuf::new(&mut [0; 1024]))
                        .map(|_| ())
                }
            }

            Fut(&r).await;

            loop {
                r.peek(&mut [0; 1024]).await?;
                r.try_read(&mut [0; 1024])?;
            }
            #[allow(unreachable_code)]
            Ok::<(), io::Error>(())
        });

        let mut acc = 0;
        while acc < 100_000 {
            w.writable().await?;
            acc += w.try_write(&[1; 1024])?;
        }

        w.forget();

        Ok(())
    });

    sim.run()
}
