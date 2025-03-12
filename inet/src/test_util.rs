use std::{
    future::Future,
    io,
    net::{IpAddr, Ipv4Addr},
    time::Duration,
};

use des::{
    net::{processing::ProcessingStack, AsyncFn, Sim},
    prelude::{Channel, ChannelDropBehaviour, ChannelMetrics},
    runtime::{Builder, RuntimeError},
};

use crate::{
    interface::{add_interface, InterfaceDef, NetworkDevice},
    utils::LinkLayerSwitch,
};

const DEFAULT_CHANNEL_METRICS: ChannelMetrics = ChannelMetrics::new(
    8_000_000,
    Duration::from_millis(20),
    Duration::ZERO,
    ChannelDropBehaviour::Queue(None),
);

pub struct SimpleSim {
    clients: Vec<IpAddr>,
    sim: Sim<()>,
    pub metrics: ChannelMetrics,
}

impl SimpleSim {
    pub fn new(stack: impl FnMut() -> ProcessingStack + 'static) -> Self {
        let mut sim = Sim::new(()).with_stack(stack);
        sim.node("switch", LinkLayerSwitch::default());

        Self {
            sim,
            clients: Vec::new(),
            metrics: DEFAULT_CHANNEL_METRICS,
        }
    }

    fn add_client(&mut self, key: &str) -> IpAddr {
        match key.parse() {
            Ok(addr) => {
                self.clients.push(addr);
                addr
            }
            Err(_) => {
                for i in 1..255 {
                    let addr = Ipv4Addr::new(192, 168, 2, i);
                    if !self.clients.contains(&addr.into()) {
                        self.clients.push(addr.into());
                        return addr.into();
                    }
                }

                panic!("no address available")
            }
        }
    }

    pub fn node<F, Fut>(&mut self, key: &str, f: F)
    where
        F: Fn() -> Fut,
        F: Send + 'static,
        Fut: Future<Output = io::Result<()>> + Send,
        Fut: 'static,
    {
        self.node_with_addr(key, key, f);
    }

    pub fn node_with_addr<F, Fut>(&mut self, key: &str, addr: &str, f: F)
    where
        F: Fn() -> Fut,
        F: Send + 'static,
        Fut: Future<Output = io::Result<()>> + Send,
        Fut: 'static,
    {
        let addr = self.add_client(addr);
        let key = key.replace(".", "_");
        self.sim.node(
            &key,
            AsyncFn::io(move |_rx| {
                let f = f();
                async move {
                    add_interface(InterfaceDef::new("en0", NetworkDevice::eth()).ip(addr))?;
                    f.await
                }
            }),
        );
        self.sim.gate(&key, "port").connect(
            self.sim.gate("switch", &format!("port-${key}")),
            Some(Channel::new(self.metrics)),
        );
    }

    pub fn node_require_join<F, Fut>(&mut self, key: &str, f: F)
    where
        F: Fn() -> Fut,
        F: Send + 'static,
        Fut: Future<Output = io::Result<()>> + Send,
        Fut: 'static,
    {
        let addr = self.add_client(key);
        let key = key.replace(".", "_");
        self.sim.node(
            &key,
            AsyncFn::io(move |_rx| {
                // TODO: add option to ensure no packet escapes the IOContext, aka rx remains empty
                let f = f();
                async move {
                    add_interface(InterfaceDef::new("en0", NetworkDevice::eth()).ip(addr))?;
                    let r = f.await;
                    r
                }
            })
            .require_join(),
        );
        self.sim.gate(&key, "port").connect(
            self.sim.gate("switch", &format!("port-${key}")),
            Some(Channel::new(self.metrics)),
        );
    }

    pub fn run(self) -> Result<(), RuntimeError> {
        let rt = Builder::seeded(123).max_time(100.0.into()).build(self.sim);
        rt.run().map(|_| ())
    }

    pub fn run_max_time(self, f: f64) -> Result<(), RuntimeError> {
        let rt = Builder::seeded(123).max_time(f.into()).build(self.sim);
        rt.run().map(|_| ())
    }
}

impl Default for SimpleSim {
    fn default() -> Self {
        let mut sim = Sim::new(()).with_stack(crate::init);
        sim.node("switch", LinkLayerSwitch::default());

        Self {
            sim,
            clients: Vec::new(),
            metrics: DEFAULT_CHANNEL_METRICS,
        }
    }
}
