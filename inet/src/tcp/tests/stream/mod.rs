use std::{io, time::Duration};

use des::{
    net::SimBuilder,
    prelude::{ChannelDropBehaviour, DatarateChannel, DatarateChannelMetrics},
    runtime::Builder,
};
use tokio::io::AsyncReadExt;

use crate::{
    dns::ToSocketAddrs,
    tcp::{TcpListener, TcpStream},
};

mod connect;
mod owned_half;
mod ref_half;
mod shutdown;
mod socketopt;
mod transmit;

async fn accpet_any_incoming_and_echo_if_possible<A: ToSocketAddrs>(binding: A) -> io::Result<()> {
    let listener = TcpListener::bind(binding).await?;
    loop {
        let (stream, _) = listener.accept().await?;
        tokio::spawn(consume_any_data_echo_if_possible(stream));
    }
}

async fn consume_any_data_echo_if_possible(mut stream: TcpStream) -> io::Result<()> {
    let mut buf = [0; 1024];
    while let n = stream.read(&mut buf).await?
        && n != 0
    {
        match stream.try_write(&buf) {
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

fn run_default_sim(mut sim: SimBuilder<()>) {
    let a = sim.gate("alice", "port");
    let b = sim.gate("bob", "port");
    a.connect_with(
        b,
        Some(DatarateChannel::new(DatarateChannelMetrics::new(
            80000,
            Duration::from_millis(200),
            Duration::ZERO,
            ChannelDropBehaviour::Queue(None),
        ))),
    );

    let _ = Builder::seeded(123)
        .max_time(100.0.into())
        .max_itr(100)
        .build(sim.freeze())
        .run();
}
