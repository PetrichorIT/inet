use des::prelude::Message;
use fxhash::FxHashMap;
use types::iface::MacAddress;

use crate::{
    ctx::IOContext,
    interface::{IfId, InterfaceName},
};

#[derive(Debug, Clone)]
pub struct NetworkBridge {
    #[allow(unused)]
    name: InterfaceName,
    addr: MacAddress,
    fib: FxHashMap<MacAddress, IfId>, // < forwarding information base
    queues: Vec<IfId>,
}

impl NetworkBridge {
    pub fn addr(&self) -> MacAddress {
        self.addr
    }

    pub fn all(&self) -> impl Iterator<Item = IfId> + '_ {
        self.queues.iter().copied()
    }

    pub(super) fn new(name: InterfaceName, addr: MacAddress) -> Self {
        NetworkBridge {
            name,
            addr,
            fib: FxHashMap::default(),
            queues: Vec::new(),
        }
    }

    pub fn add(&mut self, iface: IfId) {
        self.queues.push(iface);
    }

    pub fn lookup(&self, dst: MacAddress) -> Option<IfId> {
        self.fib.get(&dst).copied()
    }
}

impl IOContext {
    pub fn interface_forward_over_bridge(&mut self, bridge: IfId, incoming: IfId, msg: &Message) {
        // tracing::info!("forwarding over bridge {bridge:?} from {incoming:?}");

        let src = MacAddress::from(msg.header.src);
        let dst = MacAddress::from(msg.header.dst);
        let bridge = self.ifaces.bridges.get_mut(&bridge).expect("illegal state");

        let is_unicast = !(src.is_broadcast() || src.is_multicast() || src.is_unspecified());
        if is_unicast {
            bridge
                .fib
                .insert(MacAddress::from(msg.header.src), incoming);
        }

        if let Some(outgoing) = bridge.lookup(dst) {
            self.interface_forward_buffered(outgoing, msg.clone());
        } else {
            let valid = bridge
                .all()
                .filter(|ifid| *ifid != incoming)
                .collect::<Vec<_>>();
            for ifid in valid {
                self.interface_forward_buffered(ifid, msg.clone())
            }
        }
    }

    fn interface_forward_buffered(&mut self, ifid: IfId, msg: Message) {
        // tracing::info!("-> {ifid}");
        let iface = self.ifaces.get_mut(&ifid).expect("illegal state");
        let _ = iface
            .send_buffered(msg)
            .inspect_err(|e| tracing::error!("bridge forwarding failed {e:?}"));
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use des::{
        net::{Sim, handlers::AsyncHandler},
        prelude::{ChannelDropBehaviour, DatarateChannel, DatarateChannelMetrics},
        runtime::{Builder, RuntimeError},
        time::sleep,
    };
    use serial_test::serial;

    use crate::{
        UdpSocket,
        dns::sim_internal_dns_resolve,
        interface::{InterfaceDef, NetworkDevice},
        ioctx,
    };

    fn lan() -> Option<DatarateChannel> {
        Some(DatarateChannel::new(DatarateChannelMetrics::new(
            8_000_000,
            Duration::from_millis(5),
            Duration::ZERO,
            ChannelDropBehaviour::Queue(None),
        )))
    }

    #[test]
    #[serial]
    fn simple_bridging() -> Result<(), RuntimeError> {
        // des::tracing::init();

        let mut sim = Sim::new(()).with_stack(crate::stack(sim_internal_dns_resolve));
        sim.node(
            "alice",
            AsyncHandler::io(|_| async move {
                ioctx()
                    .add_interface(InterfaceDef::ethv6_autocfg(NetworkDevice::eth()))?
                    .wait_for_link_local()
                    .await;

                sleep(Duration::from_secs(5)).await;

                let sock = UdpSocket::bind("[::]:0").await?;
                sock.send_to(&[1, 2, 3, 4, 5, 6, 7, 8], "bob:100").await?;

                Ok(())
            }),
        );
        sim.node(
            "bob",
            AsyncHandler::io(|_| async move {
                ioctx()
                    .add_interface(InterfaceDef::ethv6_autocfg(NetworkDevice::eth()))?
                    .wait_for_link_local()
                    .await;

                let sock = UdpSocket::bind("[::]:100").await?;
                let mut buf = [0; 1024];
                let (n, _from) = sock.recv_from(&mut buf).await?;
                assert_eq!(&buf[..n], [1, 2, 3, 4, 5, 6, 7, 8]);

                Ok(())
            }),
        );
        sim.node(
            "charlie",
            AsyncHandler::io(|_| async move {
                ioctx()
                    .add_interface(InterfaceDef::ethv6_autocfg(NetworkDevice::eth()))?
                    .wait_for_link_local()
                    .await;
                Ok(())
            }),
        );
        sim.node(
            "bridge",
            AsyncHandler::io(|_| async move {
                let bridge = ioctx().add_bridge_interface("bridge0", None)?;
                ioctx().bridge_add_port(
                    bridge,
                    "en-a",
                    NetworkDevice::eth_select(|p| p.name == "port-a"),
                )?;
                ioctx().bridge_add_port(
                    bridge,
                    "en-b",
                    NetworkDevice::eth_select(|p| p.name == "port-b"),
                )?;
                ioctx().bridge_add_port(
                    bridge,
                    "en-c",
                    NetworkDevice::eth_select(|p| p.name == "port-c"),
                )?;
                Ok(())
            }),
        );

        // sim.node("bridge", LinkLayerSwitch::default());

        sim.gate("alice", "port")
            .connect_with(sim.gate("bridge", "port-a"), lan());
        sim.gate("bob", "port")
            .connect_with(sim.gate("bridge", "port-b"), lan());
        sim.gate("charlie", "port")
            .connect_with(sim.gate("bridge", "port-c"), lan());

        Builder::seeded(132).build(sim.freeze()).run().map(|_| ())
    }
}
