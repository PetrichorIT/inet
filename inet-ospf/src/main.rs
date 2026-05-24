use std::time::Duration;

use des::{
    Sim,
    channel::{ChannelDropBehaviour, DatarateChannel, DatarateChannelMetrics},
    gate::IntoGate,
    runtime::handlers::AsyncHandler,
};
use inet_ospf::{Config, launch};

const LAN: DatarateChannelMetrics = DatarateChannelMetrics::new(
    10_000,
    Duration::from_millis(20),
    Duration::ZERO,
    ChannelDropBehaviour::Queue(None),
);

fn main() {
    des::tracing::init();

    let mut sim = Sim::new(()).with_stack(inet::init);
    sim.node(
        "r1",
        AsyncHandler::io(|_| {
            launch(Config {
                router_id: 1,
                area_id: 1,
            })
        }),
    );
    sim.node(
        "r2",
        AsyncHandler::io(|_| {
            launch(Config {
                router_id: 2,
                area_id: 1,
            })
        }),
    );
    // sim.node("r3", AsyncHandler::io(|_| launch(Config { area_id: 1 })));

    sim.gate("r1", "link-1")
        .connect_with(sim.gate("r2", "link-1"), Some(DatarateChannel::new(LAN)));

    let _ = sim
        .max_time(60.0.into())
        .max_itr(100)
        .seeded(123)
        .build()
        .run()
        .assert_no_err();
}
