use std::net::IpAddr;

use crate::IOHandle;

use super::IOContext;
use des::{
    net::{module::current, processing::ProcessingElement},
    prelude::Message,
};

/// A plugin managing IO primitives provided by inet.
pub struct IOPlugin {
    ctx: Option<IOHandle>,
    prev: Option<IOHandle>,
}

impl IOPlugin {
    /// Creates a new plugin without defined network devices.
    pub(super) fn new(ctx: IOContext) -> Self {
        Self {
            ctx: Some(ctx.make()),
            prev: None,
        }
    }
}

impl ProcessingElement for IOPlugin {
    fn process_with(
        &mut self,
        msg: Option<Message>,
        inner: &mut dyn FnMut(Option<Message>) -> Option<Message>,
    ) -> Option<Message> {
        let io = self.ctx.take().expect("Theft");
        self.prev = IOHandle::swap_in(Some(io));

        let res = msg.and_then(|msg| IOContext::with_current(|ctx| ctx.recv(msg)));
        let res = inner(res);

        IOContext::with_current(|ctx| ctx.event_end());

        self.ctx = IOHandle::swap_in(self.prev.take());
        let ctx = self.ctx.as_mut().expect("illegal state");

        let mut ctx = ctx.0.lock().expect("failed to get lock");
        if ctx.meta_changed {
            ctx.meta_changed = false;
            if let Ok(mut prop) = current().prop::<Option<IpAddr>>("inet.meta") {
                prop.set(ctx.get_ip());
            }
        }

        res
    }
}
