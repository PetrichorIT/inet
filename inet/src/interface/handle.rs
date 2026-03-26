use std::{io::Result, net::IpAddr};

use des::prelude::try_current;
use serde::{Deserialize, Serialize};
use tokio::sync::watch;
use types::ip::{Ipv6AddrExt, Ipv6AddrScope};
use valuable::Valuable;

use crate::{
    IOHandle,
    interface::{IfId, InterfaceAddrBindings, InterfaceEvent, InterfaceFlags, InterfaceName},
};

/// A handle to an existing interface (in a given IO context).
///
/// This handle can be used to manipulate / interact with the interface and
/// its associated events.
#[derive(Debug, Clone)]
pub struct InterfaceHandle {
    pub(super) id: IfId,
    pub(super) io: IOHandle,
    pub(super) rx: watch::Receiver<InterfaceEvent>,
}

#[derive(Debug, Clone, Valuable, Serialize, Deserialize)]
pub struct InterfaceStatus {
    pub name: InterfaceName,
    pub flags: InterfaceFlags,
    pub addrs: InterfaceAddrBindings,
    pub send_q: usize,
    pub queuelen: usize,
}

impl InterfaceHandle {
    /// The interface's ID.
    pub fn id(&self) -> IfId {
        self.id
    }

    async fn wait_for(&mut self, mut f: impl FnMut(&InterfaceEvent) -> bool) {
        while !f(&*self.rx.borrow_and_update()) {
            self.rx.changed().await.expect("must not fail")
        }
    }

    /// Waits for a new link-local address to become available.
    ///
    /// Note that this method will wait only for **new** link-local addresses.
    pub async fn wait_for_link_local(&mut self) {
        self.wait_for(|e| match e {
            InterfaceEvent::AddrUp(IpAddr::V6(addr)) => addr.is_link_local(),
            _ => false,
        })
        .await
    }

    /// Waits for a new global-unicast address to become available.
    ///
    /// Note that this method will wait only for **new** global-unicast addresses.
    pub async fn wait_for_global(&mut self) {
        self.wait_for(|e| match e {
            InterfaceEvent::AddrUp(IpAddr::V6(addr)) => {
                addr.scope() == Ipv6AddrScope::UnicastGlobal
            }
            _ => false,
        })
        .await
    }

    /// Manually adds a new unicast address to the interface.
    /// This may not add the address immediately, if deduplication checks are required.
    ///
    /// # Errors
    ///
    /// This method may fail if the given interface does not support the address.
    pub fn add_addr(&self, addr: IpAddr) -> Result<()> {
        self.io
            .do_mutating_on_active_module(|ctx| ctx.interface_add_addr(&self.id.to_string(), addr))
    }

    /// Retrieves the status of the interface.
    pub fn status(&self) -> InterfaceStatus {
        self.io.do_mutating(|ctx| {
            let iface = ctx.ifaces.get(&self.id).expect("no such interface");
            iface.status()
        })
    }
}

impl InterfaceStatus {
    pub fn publish(&self) {
        if cfg!(feature = "props") {
            let Some(module) = try_current() else { return };
            module
                .prop::<InterfaceStatus>(&format!("inet.iface.{}", self.name))
                .unwrap()
                .set(self.clone());
        }
    }
}
