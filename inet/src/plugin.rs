use std::any::Any;

use super::IOContext;
use des::{
    net::plugin::Plugin,
    prelude::{Message, ModuleId},
};

/// A plugin managing IO primitives provided by inet.
pub struct IOPlugin {
    ctx: Option<Box<IOContext>>,
    prev: Option<Box<IOContext>>,
}

impl IOPlugin {
    /// Creates a new plugin without defined network devices.
    pub(super) fn new(id: ModuleId) -> Self {
        Self {
            ctx: Some(Box::new(IOContext::new(id))),
            prev: None,
        }
    }
}

impl Plugin for IOPlugin {
    fn event_start(&mut self) {
        let io = self.ctx.take().expect("Theft");
        self.prev = IOContext::swap_in(Some(io));
    }

    fn capture_incoming(&mut self, msg: Message) -> Option<Message> {
        IOContext::with_current(|ctx| ctx.recv(msg))
    }

    fn event_end(&mut self) {
        self.ctx = IOContext::swap_in(self.prev.take());
        assert!(self.ctx.is_some());
    }

    fn state(&self) -> Box<dyn Any> {
        let ip = self.ctx.as_ref().map(|ctx| ctx.get_ip()).flatten();
        // tracing::info!("returning {:?} at ", ip);
        Box::new(ip)
    }
}
