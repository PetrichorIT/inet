use std::time::Duration;

use des::{
    net::Sim,
    prelude::{Channel, ChannelDropBehaviour, ChannelMetrics},
    runtime::Builder,
};

mod connect;
mod shutdown;
mod transmit;

fn run_default_sim(mut sim: Sim<()>) {
    let a = sim.gate("alice", "port");
    let b = sim.gate("bob", "port");
    a.connect(
        b,
        Some(Channel::new(ChannelMetrics::new(
            80000,
            Duration::from_millis(200),
            Duration::ZERO,
            ChannelDropBehaviour::Queue(None),
        ))),
    );

    let _ = Builder::seeded(123)
        .max_time(100.0.into())
        .max_itr(100)
        .build(sim)
        .run();
}
