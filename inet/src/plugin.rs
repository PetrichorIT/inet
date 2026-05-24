use std::{net::IpAddr, sync::Arc};

use crate::IOHandle;

use super::IOContext;
use des::{module::current, prelude::Message, processing::ProcessingElement};

/// A plugin managing IO primitives provided by inet.
pub struct IOPlugin {
    ctx: IOHandle,
    prev: Option<IOHandle>,
}

impl IOPlugin {
    /// Creates a new plugin without defined network devices.
    pub(super) fn new(ctx: IOContext) -> Self {
        Self {
            ctx: ctx.make(),
            prev: None,
        }
    }

    pub fn handle(&self) -> IOHandle {
        self.ctx.clone()
    }
}

impl ProcessingElement for IOPlugin {
    fn process_with(
        &mut self,
        msg: Option<Message>,
        inner: &mut dyn FnMut(Option<Message>) -> Option<Message>,
    ) -> Option<Message> {
        let io = self.ctx.clone();
        self.prev = IOHandle::swap_in(Some(io.clone()));

        let res = msg.and_then(|msg| io.do_mutating(|ctx| ctx.recv(msg)));
        let res = inner(res);

        io.do_mutating(|ctx| ctx.event_end());

        let received = IOHandle::swap_in(self.prev.take()).expect("illegal state");
        assert!(Arc::ptr_eq(&self.ctx.0, &received.0));

        let mut ctx = self.ctx.0.lock().expect("failed to get lock");
        if ctx.meta_changed {
            ctx.meta_changed = false;
            if let Ok(mut prop) = current().prop::<Option<IpAddr>>("inet.meta") {
                prop.set(ctx.get_ip());
            }
        }

        res
    }
}
