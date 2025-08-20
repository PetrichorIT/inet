use std::time::Duration;

use des::{
    net::SimBuilder,
    prelude::{ChannelDropBehaviour, DatarateChannel, DatarateChannelMetrics},
    runtime::Builder,
};

mod connect;
mod shutdown;
mod transmit;

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
