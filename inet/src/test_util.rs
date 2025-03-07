use std::{future::Future, io, net::Ipv4Addr, time::Duration};

use des::{
    net::{processing::ProcessingStack, AsyncFn, Sim},
    prelude::{Channel, ChannelDropBehaviour, ChannelMetrics},
    runtime::{Builder, RuntimeError},
};

use crate::{
    interface::{add_interface, Interface, NetworkDevice},
    utils::LinkLayerSwitch,
};

pub struct SimpleSim {
    clients: Vec<Ipv4Addr>,
    sim: Sim<()>,
}

impl SimpleSim {
    pub fn new(stack: impl FnMut() -> ProcessingStack + 'static) -> Self {
        let mut sim = Sim::new(()).with_stack(stack);
        sim.node("switch", LinkLayerSwitch::default());

        Self {
            sim,
            clients: Vec::new(),
        }
    }

    fn add_client(&mut self, key: &str) -> Ipv4Addr {
        match key.parse() {
            Ok(addr) => {
                self.clients.push(addr);
                addr
            }
            Err(_) => {
                for i in 100..255 {
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
        let addr = self.add_client(key);
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
        }
    }
}
