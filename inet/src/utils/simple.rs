use std::{
    future::Future,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::Duration,
};

use des::{
    Failure, Sim, SimBuilder,
    gate::IntoGate,
    prelude::{ChannelDropBehaviour, DatarateChannel, DatarateChannelMetrics, Message, current},
    processing::ProcessingStack,
    runtime::{IntoModuleTree, handlers::AsyncHandler},
};
use tokio::sync::mpsc::Receiver;

use crate::{
    interface::{InterfaceDef, NetworkDevice},
    ioctx,
    utils::LinkLayerSwitch,
};

const DEFAULT_CHANNEL_METRICS: DatarateChannelMetrics = DatarateChannelMetrics::new(
    8_000_000,
    Duration::from_millis(20),
    Duration::ZERO,
    ChannelDropBehaviour::Queue(None),
);

pub struct SimpleSim {
    clients: Vec<IpAddr>,
    sim: SimBuilder<()>,
    pub metrics: DatarateChannelMetrics,
    pub v6: bool,
}

impl SimpleSim {
    pub fn new(stack: impl Fn() -> ProcessingStack + 'static) -> Self {
        let mut sim = Sim::new(()).with_stack(stack);
        sim.node("switch", LinkLayerSwitch::default());

        Self {
            sim,
            clients: Vec::new(),
            metrics: DEFAULT_CHANNEL_METRICS,
            v6: false,
        }
    }

    fn add_client(&mut self, key: &str) -> IpAddr {
        match key.parse() {
            Ok(addr) => {
                self.clients.push(addr);
                addr
            }
            Err(_) => {
                if self.v6 {
                    for i in 1..255 {
                        let addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, i);
                        if !self.clients.contains(&addr.into()) {
                            self.clients.push(addr.into());
                            return addr.into();
                        }
                    }
                } else {
                    for i in 1..255 {
                        let addr = Ipv4Addr::new(192, 168, 2, i);
                        if !self.clients.contains(&addr.into()) {
                            self.clients.push(addr.into());
                            return addr.into();
                        }
                    }
                }

                panic!("no address available")
            }
        }
    }

    pub fn raw<F, Fut>(&mut self, name: &str, f: F)
    where
        F: Fn(Receiver<Message>) -> Fut,
        F: Send + 'static,
        Fut: Future<Output = io::Result<()>> + Send,
        Fut: 'static,
    {
        self.module(name, AsyncHandler::io(f).require_join());
    }

    pub fn module<M: IntoModuleTree>(&mut self, name: &str, module: M) {
        self.sim.node(name, module);
        self.sim.gate(name, "port").connect_with(
            self.sim.gate_cluster("switch", "port"),
            Some(DatarateChannel::new(self.metrics)),
        );
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
            AsyncHandler::io(move |_rx| {
                let f = f();
                async move {
                    ioctx()
                        .add_interface(InterfaceDef::new("en0", NetworkDevice::eth()).ip(addr))?;
                    current().wait_for_start().await;
                    f.await
                }
            }),
        );
        self.sim.gate(&key, "port").connect_with(
            self.sim.gate_cluster("switch", "port"),
            Some(DatarateChannel::new(self.metrics)),
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
            AsyncHandler::io(move |_rx| {
                // TODO: add option to ensure no packet escapes the IOContext, aka rx remains empty
                let f = f();
                async move {
                    ioctx()
                        .add_interface(InterfaceDef::new("en0", NetworkDevice::eth()).ip(addr))?;
                    current().wait_for_start().await;
                    f.await
                }
            })
            .require_join(),
        );

        self.sim.gate(&key, "port").connect_with(
            self.sim.gate_cluster("switch", "port"), // could be done with an abstract gate, but this is more descriptive
            Some(DatarateChannel::new(self.metrics)),
        );
    }

    pub fn inner(&self) -> &SimBuilder<()> {
        &self.sim
    }

    pub fn inner_mut(&mut self) -> &mut SimBuilder<()> {
        &mut self.sim
    }

    pub fn into_inner(self) -> Sim<()> {
        self.sim.freeze()
    }

    pub fn run(self) -> Result<(), Failure> {
        let rt = self.sim.seeded(123).max_time(100.0.into()).build();
        rt.run().into_result().map(|_| ())
    }

    pub fn run_max_time(self, f: f64) -> Result<(), Failure> {
        let rt = self.sim.seeded(123).max_time(f.into()).build();
        rt.run().into_result().map(|_| ())
    }
}

impl Default for SimpleSim {
    fn default() -> Self {
        Self::new(crate::stack(crate::dns::sim_internal_dns_resolve))
    }
}

#[cfg(test)]
mod tests {
    use serial_test::serial;

    use super::*;

    #[test]
    #[serial]
    #[should_panic = "no address available"]
    fn too_many_clients() {
        let mut sim = SimpleSim::default();
        for i in 0..300 {
            sim.node_require_join(&i.to_string(), || async move { Ok(()) });
        }
    }
}
