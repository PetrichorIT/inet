use std::{
    io::{Error, ErrorKind, Result},
    net::IpAddr,
};

use des::prelude::try_current;
use serde::{Deserialize, Serialize};
use tokio::sync::watch;
use types::ip::{Ipv6AddrExt, Ipv6AddrScope};
use valuable::Valuable;

use crate::{
    IOHandle,
    interface::{IfId, InterfaceAddrBindings, InterfaceEvent, InterfaceFlags, InterfaceName},
};

#[derive(Debug)]
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
    pub fn get(name: impl AsRef<str>) -> Result<Self> {
        let io =
            IOHandle::try_current().ok_or_else(|| Error::other("could not retrive IO handle"))?;
        let (id, rx) = io
            .do_io(|ctx| {
                ctx.ifaces
                    .iter()
                    .find(|(_, v)| &*v.name == name.as_ref())
                    .map(|(k, v)| (*k, v.state.events.subscribe()))
            })
            .ok_or_else(|| Error::new(ErrorKind::NotFound, "no such interface exists"))?;

        Ok(Self { io, id, rx })
    }

    pub fn id(&self) -> IfId {
        self.id
    }

    async fn wait_for(&mut self, mut f: impl FnMut(&InterfaceEvent) -> bool) {
        while !f(&*self.rx.borrow_and_update()) {
            self.rx.changed().await.expect("must not fail")
        }
    }

    /// Waits for an addr to become available
    pub async fn wait_for_link_local(&mut self) {
        self.wait_for(|e| match e {
            InterfaceEvent::AddrUp(IpAddr::V6(addr)) => addr.is_link_local(),
            _ => false,
        })
        .await
    }

    /// Waits for an addr to become available
    pub async fn wait_for_global(&mut self) {
        self.wait_for(|e| match e {
            InterfaceEvent::AddrUp(IpAddr::V6(addr)) => {
                addr.scope() == Ipv6AddrScope::UnicastGlobal
            }
            _ => false,
        })
        .await
    }

    pub fn add_addr(&self, addr: IpAddr) -> Result<()> {
        self.io
            .do_failable(|ctx| ctx.interface_add_addr(&self.id.to_string(), addr))
    }

    pub fn status(&self) -> Result<InterfaceStatus> {
        self.io.do_failable(|ctx| {
            let Some(iface) = ctx.ifaces.get(&self.id) else {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    "no such interface exists",
                ));
            };
            Ok(iface.status())
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
