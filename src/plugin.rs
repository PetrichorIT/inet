use std::any::Any;

use super::IOContext;
use des::{net::plugin::Plugin, prelude::Message};

/// A plugin managing IO primitives provided by inet.
pub struct IOPlugin {
    ctx: Option<IOContext>,
    prev: Option<IOContext>,
}

impl IOPlugin {
    /// Creates a new plugin without defined network devices.
    pub fn new() -> Self {
        Self {
            ctx: Some(IOContext::empty()),
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
        // log::info!("returning {:?} at ", ip);
        Box::new(ip)
    }
}
