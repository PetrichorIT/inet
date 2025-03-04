use std::{future::Future, io, net::Ipv4Addr, time::Duration};

use des::{
    net::{processing::ProcessingStack, AsyncFn, Sim},
    prelude::{Channel, ChannelDropBehaviour, ChannelMetrics},
    runtime::{Builder, RuntimeResult},
};

use crate::{
    interface::{add_interface, Interface, NetworkDevice},
    utils::LinkLayerSwitch,
};

pub struct SimpleSim {
    sim: Sim<()>,
}

impl SimpleSim {
    pub fn new(stack: impl FnMut() -> ProcessingStack + 'static) -> Self {
        let mut sim = Sim::new(()).with_stack(stack);
        sim.node("switch", LinkLayerSwitch::default());

        Self { sim }
    }

    pub fn node<F, Fut>(&mut self, key: &str, f: F)
    where
        F: Fn() -> Fut,
        F: Send + 'static,
        Fut: Future<Output = io::Result<()>> + Send,
        Fut: 'static,
    {
        let addr: Ipv4Addr = key.parse().expect("key is not an ip");
        let key = key.replace(".", "_");
        self.sim.node(
            &key,
            AsyncFn::io(move |_rx| {
                let f = f();
                async move {
                    add_interface(Interface::ethv4(NetworkDevice::eth(), addr))?;
                    f.await
                }
            }),
        );
        self.sim.gate(&key, "port").connect(
            self.sim.gate("switch", &format!("port-${key}")),
            Some(Channel::new(ChannelMetrics::new(
                8_000_000,
                Duration::from_millis(20),
                Duration::ZERO,
                ChannelDropBehaviour::Queue(None),
            ))),
        );
    }

    pub fn node_require_join<F, Fut>(&mut self, key: &str, f: F)
    where
        F: Fn() -> Fut,
        F: Send + 'static,
        Fut: Future<Output = io::Result<()>> + Send,
        Fut: 'static,
    {
        let addr: Ipv4Addr = key.parse().expect("key is not an ip");
        let key = key.replace(".", "_");
        self.sim.node(
            &key,
            AsyncFn::io(move |_rx| {
                let f = f();
                async move {
                    add_interface(Interface::ethv4(NetworkDevice::eth(), addr))?;
                    f.await
                }
            })
            .require_join(),
        );
        self.sim.gate(&key, "port").connect(
            self.sim.gate("switch", &format!("port-${key}")),
            Some(Channel::new(ChannelMetrics::new(
                8_000_000,
                Duration::from_millis(20),
                Duration::ZERO,
                ChannelDropBehaviour::Queue(None),
            ))),
        );
    }

    pub fn run(self) -> RuntimeResult<Sim<()>> {
        let rt = Builder::seeded(123).max_time(100.0.into()).build(self.sim);
        rt.run()
    }

    pub fn run_max_time(self, f: f64) -> RuntimeResult<Sim<()>> {
        let rt = Builder::seeded(123).max_time(f.into()).build(self.sim);
        rt.run()
    }
}

impl Default for SimpleSim {
    fn default() -> Self {
        let mut sim = Sim::new(()).with_stack(crate::init);
        sim.node("switch", LinkLayerSwitch::default());

        Self { sim }
    }
}
