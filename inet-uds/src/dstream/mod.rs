mod listener;
mod stream;

pub use self::listener::*;
pub use self::stream::*;

#[cfg(test)]
mod tests {
    use super::*;

    use des::{Sim, runtime::handlers::AsyncHandler, runtime::random, time::sleep};
    use serial_test::serial;
    use std::{iter::repeat_with, time::Duration};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[serial]
    #[test]
    fn stream_simplex() {
        let mut sim = Sim::new(()).with_stack(inet::init);
        sim.node(
            "alice",
            AsyncHandler::io(|_| async move {
                let h1 = tokio::spawn(async move {
                    let server = UnixListener::bind("/tmp/listener").unwrap();
                    while let Ok((mut stream, from)) = server.accept().await {
                        tracing::info!("stream established from {from:?}");
                        sleep(Duration::from_secs(1)).await;

                        let mut buf = [0; 512];
                        loop {
                            let n = stream.read(&mut buf).await.unwrap();

                            if n == 0 {
                                tracing::info!("stream closed");
                                break;
                            }
                            tracing::info!("received {n} bytes");
                        }
                        break;
                    }
                });

                let h2 = tokio::spawn(async move {
                    let mut client = UnixStream::connect("/tmp/listener").await.unwrap();
                    tracing::info!("connected");
                    sleep(Duration::from_secs(1)).await;

                    client.write_all(&[42; 5000]).await.unwrap();
                });

                h1.await?;
                h2.await?;

                Ok(())
            })
            .require_join(),
        );

        let _ = sim.seeded(123).max_time(100.0.into()).build().run();
    }

    #[serial]
    #[test]
    fn stream_duplex() {
        let mut sim = Sim::new(()).with_stack(inet::init);
        sim.node(
            "alice",
            AsyncHandler::io(|_| async move {
                let h1 = tokio::spawn(async move {
                    let server = UnixListener::bind("/tmp/listener").unwrap();
                    while let Ok((mut stream, from)) = server.accept().await {
                        tracing::info!("stream established from {from:?}");
                        sleep(Duration::from_secs(1)).await;

                        let mut buf = vec![0; 5000];
                        stream.read_exact(&mut buf).await.unwrap();
                        stream.write_all(&buf).await.unwrap();
                        tracing::info!("stream closed");

                        break;
                    }
                });

                let h2 = tokio::spawn(async move {
                    let mut client = UnixStream::connect("/tmp/listener").await.unwrap();
                    tracing::info!("connected");
                    sleep(Duration::from_secs(1)).await;

                    let wbuf = repeat_with(|| random()).take(5000).collect::<Vec<_>>();
                    client.write_all(&wbuf).await.unwrap();

                    let mut rbuf = Vec::with_capacity(5000);
                    client.read_to_end(&mut rbuf).await.unwrap();

                    assert_eq!(wbuf, rbuf);
                });

                h1.await?;
                h2.await?;

                Ok(())
            })
            .require_join(),
        );

        let _ = sim.seeded(123).max_time(100.0.into()).build().run();
    }

    #[serial]
    #[test]
    fn stream_unnamed_pair() {
        let mut sim = Sim::new(()).with_stack(inet::init);
        sim.node(
            "alice",
            AsyncHandler::io(|_| async move {
                let (mut client, mut server) = UnixStream::pair().unwrap();

                let h1 = tokio::spawn(async move {
                    sleep(Duration::from_secs(1)).await;

                    let mut buf = vec![0; 5000];
                    server.read_exact(&mut buf).await.unwrap();
                    server.write_all(&buf).await.unwrap();
                    tracing::info!("stream closed");
                });

                let h2 = tokio::spawn(async move {
                    sleep(Duration::from_secs(1)).await;

                    let wbuf = repeat_with(|| random()).take(5000).collect::<Vec<_>>();
                    client.write_all(&wbuf).await.unwrap();

                    let mut rbuf = Vec::with_capacity(5000);
                    client.read_to_end(&mut rbuf).await.unwrap();

                    assert_eq!(wbuf, rbuf);
                });

                h1.await?;
                h2.await?;

                Ok(())
            })
            .require_join(),
        );

        let _ = sim.seeded(123).max_time(100.0.into()).build().run();
    }
}
